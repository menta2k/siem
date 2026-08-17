// Package correlate joins the events that describe one request into a single record.
//
// The pipeline is deliberately split in two halves that fail independently:
//
//	Worker  consumes the normalized topic and files each event into its windows.
//	Closer  polls for windows whose deadline has passed and emits their records.
//
// Splitting them is what lets correlation fall behind without applying backpressure to
// ingestion. A stalled closer costs delayed records; a stalled ingest path costs events.
package correlate

import (
	"net"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/normalize"
)

// toRow projects a stored window member back into the shape the grouper expects.
func toRow(tenantID uuid.UUID, m window.Member) chdata.NormalizedEvent {
	return chdata.NormalizedEvent{
		TenantID:        tenantID,
		EventID:         m.EventID,
		EventTime:       m.EventTime,
		Vendor:          m.Vendor,
		VendorRequestID: m.VendorRequestID,
		LinkedRequestID: m.LinkedRequestID,
		ClientIP:        net.ParseIP(m.ClientIP),
		ClientIPShared:  m.ClientIPShared,
		ClientASN:       m.ClientASN,
		ClientCountry:   m.ClientCountry,
		RequestHost:     m.RequestHost,
		RequestPath:     m.RequestPath,
		RequestMethod:   m.RequestMethod,
		Verdict:         m.Verdict,
		RuleID:          m.RuleID,
		RuleIDs:         m.RuleIDs,
		Score:           m.Score,
		ScoreKind:       m.ScoreKind,
	}
}

// toMember projects a normalized event into the compact form the windows persist.
func toMember(event chdata.NormalizedEvent) window.Member {
	member := window.Member{
		EventID:         event.EventID,
		Vendor:          event.Vendor,
		EventTime:       event.EventTime,
		VendorRequestID: event.VendorRequestID,
		LinkedRequestID: event.LinkedRequestID,
		ClientIPShared:  event.ClientIPShared,
		ClientASN:       event.ClientASN,
		ClientCountry:   event.ClientCountry,
		RequestHost:     event.RequestHost,
		RequestPath:     event.RequestPath,
		RequestMethod:   event.RequestMethod,
		Verdict:         event.Verdict,
		RuleID:          event.RuleID,
		RuleIDs:         event.RuleIDs,
		Score:           event.Score,
		ScoreKind:       event.ScoreKind,
	}
	if event.ClientIP != nil {
		member.ClientIP = event.ClientIP.String()
	}
	return member
}

// buildRecord turns a resolved group into the row that gets written.
//
// Version and Amended are left to the caller: whether this is a first emission or an
// amendment is a property of the window's history, not of its membership.
func buildRecord(
	tenantID uuid.UUID, g group.Group, scoreThreshold float32,
) chdata.CorrelatedRequest {
	members := sortedMembers(g)

	record := chdata.CorrelatedRequest{
		TenantID:       tenantID,
		WindowStart:    windowStart(g, members),
		FirstEventTime: members[0].Row.EventTime.UTC(),
		LastEventTime:  members[len(members)-1].Row.EventTime.UTC(),
		Vendors:        g.Vendors(),
		Verdicts:       map[string]string{},
		RuleIDs:        map[string]string{},
		MatchedRuleIDs: map[string][]string{},
		Scores:         map[string]float32{},
		JoinSignals:    signalStrings(g.Key.Signals),
		JoinTier:       uint8(g.Key.Tier),
		Confidence:     string(g.Confidence),
		CandidateCount: clampToByte(g.CandidateCount),
	}
	record.VendorCount = clampToByte(len(record.Vendors))

	verdicts := make([]normalize.VendorVerdict, 0, len(members))
	for _, m := range members {
		record.EventIDs = append(record.EventIDs, m.Row.EventID)

		// Vendor-keyed maps: the point of a correlated record is that an analyst can
		// see WHICH vendor said what. Flattening these to a single value would discard
		// exactly the disagreement the record exists to surface.
		record.Verdicts[m.Row.Vendor] = m.Row.Verdict
		if m.Row.RuleID != "" {
			record.RuleIDs[m.Row.Vendor] = m.Row.RuleID
		}
		// EVERY rule the vendor matched, beside the one that decided. A Cloudflare rule in
		// log mode does not terminate evaluation, so the decision above is often a later
		// `skip` and the log-mode match — the thing a migration is measuring — would be
		// dropped here. Appended rather than assigned: a record can hold more than one
		// event from the same vendor, and each brings its own matches.
		record.MatchedRuleIDs[m.Row.Vendor] = appendUnique(
			record.MatchedRuleIDs[m.Row.Vendor], m.Row.RuleIDs)
		if m.Row.Score != nil {
			record.Scores[m.Row.Vendor] = *m.Row.Score
		}

		verdicts = append(verdicts, normalize.VendorVerdict{
			Vendor: m.Row.Vendor, Verdict: m.Row.Verdict,
			Score: m.Row.Score, ScoreKind: m.Row.ScoreKind,
		})
	}

	applyRequestShape(&record, members)

	classification := normalize.Classify(verdicts, scoreThreshold)
	record.CombinedOutcome = classification.CombinedOutcome
	record.HasDisagreement = classification.Disagreement
	record.DisagreementKind = string(classification.Kind)

	return record
}

// sortedMembers orders a group's events by time so first/last are unambiguous.
func sortedMembers(g group.Group) []group.Event {
	members := make([]group.Event, len(g.Members))
	copy(members, g.Members)
	sort.SliceStable(members, func(i, j int) bool {
		return members[i].Row.EventTime.Before(members[j].Row.EventTime)
	})
	return members
}

// windowStart is the record's partition key, so it must never be zero.
//
// Tier-1 keys carry no window — an exact identifier does not depend on time — so the
// earliest event's own window stands in. A zero here would file the record under
// 1970 and the retention TTL would drop it on the next pass.
func windowStart(g group.Group, members []group.Event) time.Time {
	if !g.Key.WindowStart.IsZero() {
		return g.Key.WindowStart.UTC()
	}
	return keys.WindowStart(members[0].Row.EventTime, keys.DefaultSettings().Window)
}

// applyRequestShape copies the request identity onto the record.
//
// The first member that actually reported a field wins. Vendors differ in what they
// log — a WAF may omit the host, a bot manager may omit the method — so taking the
// values from one designated member would leave holes that the others could fill.
func applyRequestShape(record *chdata.CorrelatedRequest, members []group.Event) {
	for _, m := range members {
		if record.ClientIP == nil && m.Row.ClientIP != nil {
			record.ClientIP = m.Row.ClientIP
		}
		if record.RequestHost == "" {
			record.RequestHost = m.Row.RequestHost
		}
		if record.RequestPath == "" {
			record.RequestPath = m.Row.RequestPath
		}
		if record.RequestMethod == "" {
			record.RequestMethod = m.Row.RequestMethod
		}
		// Shared is sticky: if ANY vendor saw the client behind a shared address, the
		// join is uncertain regardless of what the others reported.
		record.ClientIPShared = record.ClientIPShared || m.Row.ClientIPShared
	}

	// Network attribution is NOT first-member-wins. Only the vendors at the front of the
	// path can see the client's own network; the ones behind the CDN see the CDN. See
	// clientGeo.
	if record.ClientASN == 0 || record.ClientCountry == "" {
		asn, country := clientGeo(members)
		if record.ClientASN == 0 {
			record.ClientASN = asn
		}
		if record.ClientCountry == "" {
			record.ClientCountry = country
		}
	}
}

func signalStrings(signals []keys.Signal) []string {
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		out = append(out, string(s))
	}
	return out
}

// clampToByte saturates rather than wrapping. The columns are UInt8, and a window with
// 256 members must read as "many", not as zero.
func clampToByte(n int) uint8 {
	switch {
	case n < 0:
		return 0
	case n > 255:
		return 255
	default:
		return uint8(n)
	}
}

// appendUnique adds the rules not already listed, preserving the order they arrived in.
//
// Deduplicated because the same rule matching two events of one request is one rule, and a
// stage that counts requests per rule would otherwise count that request twice.
func appendUnique(existing, incoming []string) []string {
	for _, rule := range incoming {
		if rule == "" || slices.Contains(existing, rule) {
			continue
		}
		existing = append(existing, rule)
	}
	return existing
}
