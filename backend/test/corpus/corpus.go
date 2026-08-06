// Package corpus builds the labelled replay dataset that makes correlation accuracy
// measurable.
//
// SC-004 requires ≥95% of multi-vendor requests to join correctly, with a false-join
// rate below 1%. Neither number means anything without ground truth: you cannot
// measure a join rate against data where nobody knows which events actually belong
// together. This package generates the events AND the answer key.
//
// The corpus is generated rather than hand-written for two reasons: it must be large
// enough for a percentage to be meaningful, and it must be deterministic, so a
// regression in the join logic shows up as the same failure on every run rather than
// a flaky one.
package corpus

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/menta2k/siem/internal/vendors"
)

// Base time for the corpus. Fixed, never time.Now: a corpus that shifts with the
// clock cannot be compared against a stored answer key.
var baseTime = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

// EventKey identifies one vendor event in the answer key.
type EventKey struct {
	Vendor    string `json:"vendor"`
	RequestID string `json:"request_id"`
}

func (k EventKey) String() string { return k.Vendor + ":" + k.RequestID }

// ExpectedJoin is one ground-truth answer: these events describe the same request.
type ExpectedJoin struct {
	// Name identifies the scenario for a failure message.
	Name string `json:"name"`
	// Events are the vendor events that MUST end up in one correlated record.
	Events []EventKey `json:"events"`
	// Tier is the join mechanism this scenario should exercise: 1 for an exact
	// shared request id, 2 for the heuristic.
	Tier int `json:"tier"`
	// Confidence is the minimum acceptable confidence. A NAT scenario that joins at
	// medium is a failure even though the join itself is right, because asserting
	// certainty the platform does not have is what drives the false-join rate up.
	Confidence string `json:"confidence"`
	// Disagreement is the classification the record must carry.
	Disagreement string `json:"disagreement"`
	// MustNotJoin lists events that must NOT be pulled into this record. This is what
	// measures the false-join rate — a join rate alone can be gamed by joining
	// everything.
	MustNotJoin []EventKey `json:"must_not_join,omitempty"`
}

// Corpus is the generated dataset plus its answer key.
type Corpus struct {
	Cloudflare []byte         `json:"-"`
	F5         []byte         `json:"-"`
	DataDome   []byte         `json:"-"`
	Expected   []ExpectedJoin `json:"expected"`
	// SingleVendor names events that legitimately have no counterpart. They must
	// produce single-vendor records, not be discarded and not be forced into a join.
	SingleVendor []EventKey `json:"single_vendor"`
}

// MultiVendorCount returns how many requests were seen by two or more vendors, which
// is the denominator for the join rate SC-004 measures.
func (c Corpus) MultiVendorCount() int {
	count := 0
	for _, join := range c.Expected {
		if len(join.Events) >= 2 {
			count++
		}
	}
	return count
}

// builder accumulates events across the scenarios.
type builder struct {
	cloudflare []string
	f5         []map[string]any
	datadome   []map[string]any
	expected   []ExpectedJoin
	single     []EventKey
	seq        int
}

// Build generates the corpus.
func Build() (Corpus, error) {
	b := &builder{}

	b.addTierOneSharedRequestID()
	b.addTierTwoCleanMatches()
	b.addNATAmbiguity()
	b.addDisagreements()
	b.addScoreConflict()
	b.addSingleVendor()
	b.addNearMisses()

	f5Payload, err := json.Marshal(b.f5)
	if err != nil {
		return Corpus{}, fmt.Errorf("encode f5 corpus: %w", err)
	}
	datadomePayload, err := json.Marshal(b.datadome)
	if err != nil {
		return Corpus{}, fmt.Errorf("encode datadome corpus: %w", err)
	}

	return Corpus{
		Cloudflare:   []byte(strings.Join(b.cloudflare, "\n")),
		F5:           f5Payload,
		DataDome:     datadomePayload,
		Expected:     b.expected,
		SingleVendor: b.single,
	}, nil
}

// at returns a timestamp offset from the corpus base.
func at(offset time.Duration) time.Time { return baseTime.Add(offset) }

// ---------------------------------------------------------------- scenarios

// Tier 1: a customer propagates Cloudflare's RayID into the other vendors' logs.
// These must join exactly, at high confidence, with no reliance on timing.
func (b *builder) addTierOneSharedRequestID() {
	for i := range 40 {
		rayID := fmt.Sprintf("tier1-ray-%03d", i)
		offset := time.Duration(i) * time.Second

		// Deliberately spread the vendors' timestamps 4 seconds apart. A tier-1 join
		// must not depend on them being close — that is the whole point of an exact id.
		b.cloudflare = append(b.cloudflare, b.cfEvent(rayID, "203.0.113.10", "/checkout",
			"POST", at(offset), "block", 403))
		b.f5 = append(b.f5, b.f5Event(rayID, "203.0.113.10", "/checkout", "POST",
			at(offset+4*time.Second), "blocked"))
		b.datadome = append(b.datadome, b.ddEvent(rayID, "203.0.113.10", "/checkout",
			"POST", at(offset+2*time.Second), "BLOCK", 95))

		b.expected = append(b.expected, ExpectedJoin{
			Name: "tier1/" + rayID,
			Events: []EventKey{
				{vendors.Cloudflare, rayID}, {vendors.F5, rayID}, {vendors.DataDome, rayID},
			},
			Tier: 1, Confidence: "high", Disagreement: "none",
		})
	}
}

// Tier 2: no shared id, but the same client, host, path, method and a close time.
// These are the joins the heuristic exists for.
func (b *builder) addTierTwoCleanMatches() {
	for i := range 40 {
		offset := time.Duration(100+i) * time.Second
		ip := fmt.Sprintf("198.51.100.%d", (i%200)+1)
		path := fmt.Sprintf("/api/item/%d", i)

		cfID := fmt.Sprintf("tier2-cf-%03d", i)
		f5ID := fmt.Sprintf("tier2-f5-%03d", i)
		ddID := fmt.Sprintf("tier2-dd-%03d", i)

		b.cloudflare = append(b.cloudflare, b.cfEvent(cfID, ip, path, "GET",
			at(offset), "allow", 200))
		b.f5 = append(b.f5, b.f5Event(f5ID, ip, path, "GET",
			at(offset+time.Second), "passed"))
		b.datadome = append(b.datadome, b.ddEvent(ddID, ip, path, "GET",
			at(offset+2*time.Second), "ALLOW", 8))

		b.expected = append(b.expected, ExpectedJoin{
			Name: fmt.Sprintf("tier2/clean-%03d", i),
			Events: []EventKey{
				{vendors.Cloudflare, cfID}, {vendors.F5, f5ID}, {vendors.DataDome, ddID},
			},
			Tier: 2, Confidence: "medium", Disagreement: "none",
		})
	}
}

// NAT: many distinct clients behind one address. The join is probably right, but the
// platform cannot be sure — it must say so by degrading confidence rather than
// asserting a match. This is the scenario that protects the <1% false-join budget.
func (b *builder) addNATAmbiguity() {
	const natIP = "100.64.12.9" // carrier-grade NAT

	for i := range 20 {
		offset := time.Duration(300+i) * time.Second
		cfID := fmt.Sprintf("nat-cf-%03d", i)
		f5ID := fmt.Sprintf("nat-f5-%03d", i)

		b.cloudflare = append(b.cloudflare, b.cfEvent(cfID, natIP, "/api/search", "GET",
			at(offset), "allow", 200))
		b.f5 = append(b.f5, b.f5Event(f5ID, natIP, "/api/search", "GET",
			at(offset), "passed"))

		b.expected = append(b.expected, ExpectedJoin{
			Name: fmt.Sprintf("nat/ambiguous-%03d", i),
			Events: []EventKey{
				{vendors.Cloudflare, cfID}, {vendors.F5, f5ID},
			},
			Tier: 2, Confidence: "low", Disagreement: "none",
		})
	}
}

// Disagreements: the reason the product exists. One vendor allowed, another blocked.
func (b *builder) addDisagreements() {
	for i := range 25 {
		offset := time.Duration(500+i) * time.Second
		ip := fmt.Sprintf("203.0.113.%d", (i%200)+1)
		path := fmt.Sprintf("/admin/%d", i)

		cfID := fmt.Sprintf("disagree-cf-%03d", i)
		f5ID := fmt.Sprintf("disagree-f5-%03d", i)

		// Cloudflare let it through; F5 blocked the same request.
		b.cloudflare = append(b.cloudflare, b.cfEvent(cfID, ip, path, "GET",
			at(offset), "allow", 200))
		b.f5 = append(b.f5, b.f5Event(f5ID, ip, path, "GET",
			at(offset+time.Second), "blocked"))

		b.expected = append(b.expected, ExpectedJoin{
			Name: fmt.Sprintf("disagreement/allow-vs-block-%03d", i),
			Events: []EventKey{
				{vendors.Cloudflare, cfID}, {vendors.F5, f5ID},
			},
			Tier: 2, Confidence: "medium", Disagreement: "allow_vs_block",
		})
	}
}

// Score conflict: every vendor allowed the request, but DataDome scored it as a bot.
// A verdict-only comparison would call this agreement and miss it entirely.
func (b *builder) addScoreConflict() {
	for i := range 15 {
		offset := time.Duration(700+i) * time.Second
		ip := fmt.Sprintf("192.0.2.%d", (i%200)+1)
		path := fmt.Sprintf("/api/price/%d", i)

		cfID := fmt.Sprintf("conflict-cf-%03d", i)
		ddID := fmt.Sprintf("conflict-dd-%03d", i)

		b.cloudflare = append(b.cloudflare, b.cfEvent(cfID, ip, path, "GET",
			at(offset), "allow", 200))
		// Allowed, but scored 92 — a scraper the WAF did not recognize.
		b.datadome = append(b.datadome, b.ddEvent(ddID, ip, path, "GET",
			at(offset+time.Second), "ALLOW", 92))

		b.expected = append(b.expected, ExpectedJoin{
			Name: fmt.Sprintf("disagreement/score-conflict-%03d", i),
			Events: []EventKey{
				{vendors.Cloudflare, cfID}, {vendors.DataDome, ddID},
			},
			Tier: 2, Confidence: "medium", Disagreement: "score_conflict",
		})
	}
}

// Single-vendor traffic is normal, not an error: plenty of hostnames sit behind only
// one vendor. These must become single-vendor records, never be discarded.
func (b *builder) addSingleVendor() {
	for i := range 30 {
		offset := time.Duration(900+i) * time.Second
		cfID := fmt.Sprintf("solo-cf-%03d", i)

		b.cloudflare = append(b.cloudflare, b.cfEvent(cfID,
			fmt.Sprintf("198.18.0.%d", (i%200)+1),
			fmt.Sprintf("/cf-only/%d", i), "GET", at(offset), "allow", 200))

		b.single = append(b.single, EventKey{vendors.Cloudflare, cfID})
	}
}

// Near misses: events that look joinable but are NOT the same request. These are the
// trap. A correlator that widens its window or loosens its key to lift the join rate
// will start joining these, and the false-join rate will catch it.
func (b *builder) addNearMisses() {
	for i := range 20 {
		offset := time.Duration(1100+i*30) * time.Second
		ip := fmt.Sprintf("203.0.113.%d", 200+(i%50))
		path := "/api/orders"

		cfID := fmt.Sprintf("nearmiss-cf-%03d", i)
		// Same client, host, path and method — but 25 seconds later, far outside the
		// 5-second correlation window. Two genuinely separate requests.
		f5ID := fmt.Sprintf("nearmiss-f5-%03d", i)

		b.cloudflare = append(b.cloudflare, b.cfEvent(cfID, ip, path, "GET",
			at(offset), "allow", 200))
		b.f5 = append(b.f5, b.f5Event(f5ID, ip, path, "GET",
			at(offset+25*time.Second), "passed"))

		b.expected = append(b.expected,
			ExpectedJoin{
				Name:        fmt.Sprintf("nearmiss/cloudflare-%03d", i),
				Events:      []EventKey{{vendors.Cloudflare, cfID}},
				Tier:        0,
				Confidence:  "high",
				MustNotJoin: []EventKey{{vendors.F5, f5ID}},
			},
			ExpectedJoin{
				Name:        fmt.Sprintf("nearmiss/f5-%03d", i),
				Events:      []EventKey{{vendors.F5, f5ID}},
				Tier:        0,
				Confidence:  "high",
				MustNotJoin: []EventKey{{vendors.Cloudflare, cfID}},
			},
		)
	}
}

// ---------------------------------------------------------------- event shapes

func (b *builder) cfEvent(
	rayID, ip, path, method string, ts time.Time, action string, status int,
) string {
	b.seq++
	return fmt.Sprintf(
		`{"RayID":%q,"EdgeStartTimestamp":%q,"ClientIP":%q,"ClientASN":64512,`+
			`"ClientCountry":"de","ClientRequestHost":"shop.example.com",`+
			`"ClientRequestURI":%q,"ClientRequestMethod":%q,`+
			`"ClientRequestUserAgent":"Mozilla/5.0","EdgeResponseStatus":%d,`+
			`"SecurityAction":%q,"ZoneName":"example.com"}`,
		rayID, ts.Format(time.RFC3339Nano), ip, path, method, status, action)
}

func (b *builder) f5Event(
	supportID, ip, path, method string, ts time.Time, status string,
) map[string]any {
	b.seq++
	event := map[string]any{
		"support_id":     supportID,
		"date_time":      ts.Format("2006-01-02 15:04:05"),
		"ip_client":      ip,
		"method":         method,
		"uri":            path,
		"request_status": status,
		"policy_name":    "prod_waf_policy",
		"geo_location":   "DE",
		"virtual_server": "/Common/vs_shop_https",
		"host":           "shop.example.com",
		"response_code":  200,
	}
	if status == "blocked" {
		event["response_code"] = 403
		event["attack_type"] = "SQL-Injection"
		event["violations"] = "Attack signature detected"
	}
	return event
}

func (b *builder) ddEvent(
	requestID, ip, path, method string, ts time.Time, action string, score int,
) map[string]any {
	b.seq++
	status := 200
	if action == "BLOCK" {
		status = 403
	}
	return map[string]any{
		"requestid": requestID,
		"timestamp": ts.UnixMilli(),
		"ip":        ip,
		"host":      "shop.example.com",
		"uri":       path,
		"method":    method,
		"status":    status,
		"ua":        "Mozilla/5.0",
		"botscore":  score,
		"isbot":     score > 50,
		"action":    action,
		"country":   "DE",
		"accountid": "acct_corpus",
	}
}
