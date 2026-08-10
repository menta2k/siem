package correlate

import (
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
)

// mergeRecords folds a freshly closed window into the record already stored under the
// same correlation id.
//
// WITHOUT THIS, A LATE ARRIVAL DESTROYS WHAT IT SHOULD COMPLETE. A correlation id is
// derived from the window key, so it is stable forever — but the window's MEMBER state
// in Redis is not: it expires with the lateness bound. An event arriving after that
// refills an empty window, and the closer, finding the id already stored, writes it as
// an amendment. The amendment carries only the late event, so a four-vendor record is
// replaced by a one-vendor one. The analyst who bookmarked it loses the very evidence
// the record existed to hold.
//
// That is not a hypothetical either. A thirty-minute Logpush outage put every Cloudflare
// event two hours behind, far outside the fifteen-minute bound, and the correlated
// records for that period are single-vendor with no path back.
//
// Merging makes a late arrival ADDITIVE at any delay, which is what "durable" has to
// mean here: the platform's job is to say what every vendor thought of one request, and
// arriving late is not a reason to forget what the others said.
//
// The merge is deliberately UNION-BIASED. Where the two disagree about a scalar the
// fresher value wins, because it was computed from at least as much evidence; where they
// hold sets, both are kept.
func mergeRecords(
	stored, fresh chdata.CorrelatedRequest, scoreThreshold float32,
) chdata.CorrelatedRequest {
	merged := fresh

	merged.EventIDs = unionStrings(stored.EventIDs, fresh.EventIDs)
	merged.Vendors = unionStrings(stored.Vendors, fresh.Vendors)
	merged.VendorCount = clampToByte(len(merged.Vendors))

	// Per-vendor views. The fresh side wins for a vendor present in both: it is a newer
	// reading of that same vendor, not a second opinion.
	merged.Verdicts = mergeStringMap(stored.Verdicts, fresh.Verdicts)
	merged.RuleIDs = mergeStringMap(stored.RuleIDs, fresh.RuleIDs)
	merged.Scores = mergeFloatMap(stored.Scores, fresh.Scores)

	// The span has to cover both halves, or the record understates how far apart the
	// vendors observed the request — which is the number an analyst reads to judge
	// clock skew against propagation delay.
	if !stored.FirstEventTime.IsZero() && stored.FirstEventTime.Before(merged.FirstEventTime) {
		merged.FirstEventTime = stored.FirstEventTime
	}
	if stored.LastEventTime.After(merged.LastEventTime) {
		merged.LastEventTime = stored.LastEventTime
	}
	if !stored.WindowStart.IsZero() && stored.WindowStart.Before(merged.WindowStart) {
		merged.WindowStart = stored.WindowStart
	}

	merged = mergeRequestShape(merged, stored)
	merged.JoinSignals = unionStrings(stored.JoinSignals, fresh.JoinSignals)

	// The join is only ever as good as the STRONGEST evidence for it. A late event that
	// joined on a shared identifier does not weaken a record that was already exact, and
	// an exact partner arriving late upgrades one that was heuristic.
	if strongerTier(stored.JoinTier, merged.JoinTier) {
		merged.JoinTier = stored.JoinTier
		merged.Confidence = stored.Confidence
	}
	// Candidates competed within one window. The merged record spans two closings, so
	// the larger count is the honest one.
	merged.CandidateCount = max(stored.CandidateCount, merged.CandidateCount)

	// Recomputed rather than carried over: a vendor added by the merge can turn agreement
	// into a disagreement, which is the single most important field on the record.
	merged.CombinedOutcome, merged.HasDisagreement, merged.DisagreementKind =
		classifyMerged(merged, scoreThreshold)

	return merged
}

// mergeRequestShape fills any field the fresh side left empty from the stored one.
//
// A late arrival is often a single vendor that reports less than the group did — a
// DataDome-derived row carries no client address at all — so taking the fresh side
// wholesale would blank fields the record already had.
func mergeRequestShape(
	merged, stored chdata.CorrelatedRequest,
) chdata.CorrelatedRequest {
	if merged.ClientIP == nil {
		merged.ClientIP = stored.ClientIP
	}
	if merged.ClientASN == 0 {
		merged.ClientASN = stored.ClientASN
	}
	if merged.ClientCountry == "" {
		merged.ClientCountry = stored.ClientCountry
	}
	if merged.RequestHost == "" {
		merged.RequestHost = stored.RequestHost
	}
	if merged.RequestPath == "" {
		merged.RequestPath = stored.RequestPath
	}
	if merged.RequestMethod == "" {
		merged.RequestMethod = stored.RequestMethod
	}
	// Sticky, exactly as it is within one window: if either closing saw the client
	// behind a shared address, the join is uncertain regardless of the other.
	merged.ClientIPShared = merged.ClientIPShared || stored.ClientIPShared
	return merged
}

// classifyMerged re-derives the outcome from the merged per-vendor verdicts.
func classifyMerged(
	record chdata.CorrelatedRequest, scoreThreshold float32,
) (outcome string, disagreement bool, kind string) {
	verdicts := make([]normalize.VendorVerdict, 0, len(record.Verdicts))
	for vendor, verdict := range record.Verdicts {
		v := normalize.VendorVerdict{Vendor: vendor, Verdict: verdict}
		if score, ok := record.Scores[vendor]; ok {
			s := score
			v.Score = &s
			v.ScoreKind = vendors.ScoreKindBot
		}
		verdicts = append(verdicts, v)
	}

	classification := normalize.Classify(verdicts, scoreThreshold)
	return classification.CombinedOutcome, classification.Disagreement,
		string(classification.Kind)
}

// strongerTier reports whether a is a better join than b.
//
// Tier 1 (a shared identifier) beats tier 2 (shape and time), which beats tier 0 (no
// join at all). The numbering runs the wrong way for a plain comparison, and zero means
// "none" rather than "best", so this is spelled out.
func strongerTier(a, b uint8) bool {
	rank := func(tier uint8) int {
		switch tier {
		case 1:
			return 2
		case 2:
			return 1
		default:
			return 0
		}
	}
	return rank(a) > rank(b)
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if value == "" {
				continue
			}
			if _, duplicate := seen[value]; duplicate {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func mergeStringMap(stored, fresh map[string]string) map[string]string {
	out := make(map[string]string, len(stored)+len(fresh))
	for key, value := range stored {
		out[key] = value
	}
	for key, value := range fresh {
		out[key] = value
	}
	return out
}

func mergeFloatMap(stored, fresh map[string]float32) map[string]float32 {
	out := make(map[string]float32, len(stored)+len(fresh))
	for key, value := range stored {
		out[key] = value
	}
	for key, value := range fresh {
		out[key] = value
	}
	return out
}
