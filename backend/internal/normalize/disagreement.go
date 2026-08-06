package normalize

import (
	"github.com/menta2k/siem/internal/vendors"
)

// DisagreementKind classifies conflicting verdicts across vendors (FR-017).
type DisagreementKind string

// The disagreement classifications.
const (
	DisagreementNone             DisagreementKind = "none"
	DisagreementAllowVsBlock     DisagreementKind = "allow_vs_block"
	DisagreementAllowVsChallenge DisagreementKind = "allow_vs_challenge"
	DisagreementScoreConflict    DisagreementKind = "score_conflict"
)

// VendorVerdict is one vendor's contribution to a correlated request.
type VendorVerdict struct {
	Vendor  string
	Verdict string
	Score   *float32
	// ScoreKind distinguishes a bot score from a threat score. Only bot scores drive
	// a score conflict: a WAF's threat rating on an allowed request is a severity
	// hint, not a claim that the request was automated.
	ScoreKind string
}

// Classification is the outcome of comparing vendors' verdicts.
type Classification struct {
	Kind DisagreementKind
	// CombinedOutcome is the most restrictive verdict any vendor reached.
	CombinedOutcome string
	// Disagreement reports whether the record should be flagged.
	Disagreement bool
}

// DefaultScoreConflictThreshold is the normalized bot score above which an allowed
// request is treated as a conflict. Tenant-configurable.
const DefaultScoreConflictThreshold float32 = 0.8

// Classify compares the verdicts on one correlated request.
//
// A single-vendor record is never a disagreement: one vendor cannot disagree with
// itself, and marking it as one would swamp the disagreement rate on single-vendor
// hostnames until the signal was worthless.
func Classify(verdicts []VendorVerdict, scoreThreshold float32) Classification {
	if scoreThreshold <= 0 {
		scoreThreshold = DefaultScoreConflictThreshold
	}

	outcomes := make([]string, 0, len(verdicts))
	for _, v := range verdicts {
		outcomes = append(outcomes, v.Verdict)
	}
	combined := vendors.MostRestrictive(outcomes...)

	if len(verdicts) < 2 {
		return Classification{Kind: DisagreementNone, CombinedOutcome: combined}
	}

	var sawAllowed, sawBlocked, sawChallenged bool
	for _, v := range verdicts {
		switch v.Verdict {
		case vendors.VerdictAllowed:
			sawAllowed = true
		case vendors.VerdictBlocked, vendors.VerdictRateLimited:
			sawBlocked = true
		case vendors.VerdictChallenged:
			sawChallenged = true
		}
	}

	// Ordered by severity: an allow-vs-block conflict is the one an analyst most
	// needs to see, so it wins when a record somehow exhibits several.
	switch {
	case sawAllowed && sawBlocked:
		return Classification{
			Kind: DisagreementAllowVsBlock, CombinedOutcome: combined, Disagreement: true,
		}
	case sawAllowed && sawChallenged:
		return Classification{
			Kind: DisagreementAllowVsChallenge, CombinedOutcome: combined, Disagreement: true,
		}
	}

	// Every vendor allowed it, but one scored it as automated. Without this case a
	// verdict-only comparison would call it agreement and the conflict would never
	// surface — which is precisely the class of miss the product exists to catch.
	if allAllowed(verdicts) && hasHighBotScore(verdicts, scoreThreshold) {
		return Classification{
			Kind: DisagreementScoreConflict, CombinedOutcome: combined, Disagreement: true,
		}
	}

	return Classification{Kind: DisagreementNone, CombinedOutcome: combined}
}

func allAllowed(verdicts []VendorVerdict) bool {
	for _, v := range verdicts {
		if v.Verdict != vendors.VerdictAllowed {
			return false
		}
	}
	return true
}

// hasHighBotScore reports whether any vendor scored the request as likely automated.
func hasHighBotScore(verdicts []VendorVerdict, threshold float32) bool {
	for _, v := range verdicts {
		// Only a bot score counts. A WAF's threat rating on an allowed request means
		// "this looked risky", not "this was a machine", and treating the two alike
		// would flood the conflict category with ordinary WAF noise.
		if v.ScoreKind != vendors.ScoreKindBot || v.Score == nil {
			continue
		}
		if *v.Score >= threshold {
			return true
		}
	}
	return false
}
