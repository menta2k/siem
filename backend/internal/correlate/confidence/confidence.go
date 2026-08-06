// Package confidence scores how much trust a cross-vendor join deserves.
//
// The rule the whole SC-004 budget rests on: an ambiguous join is PUBLISHED as
// ambiguous, not suppressed and not asserted. Suppressing it loses a join the analyst
// probably wanted; asserting it inflates the false-join rate and, worse, teaches
// analysts to trust joins that do not deserve it.
package confidence

import (
	"github.com/menta2k/siem/internal/correlate/keys"
)

// Level is the confidence attached to a correlated record.
type Level string

// The confidence levels, matching the `confidence` column and the API enum.
const (
	High   Level = "high"
	Medium Level = "medium"
	Low    Level = "low"
)

// Input is what the scorer needs to reach a verdict.
type Input struct {
	// Tier is the join mechanism that produced the record.
	Tier keys.Tier
	// Ambiguous marks a key derived from a shared client address.
	Ambiguous bool
	// CandidateCount is how many events competed for this join. More than one means
	// the window held several plausible partners and the chosen one may be wrong.
	CandidateCount int
	// VendorCount is how many distinct vendors contributed.
	VendorCount int
}

// Score returns the confidence for a join.
func Score(in Input) Level {
	// A single-vendor record involved no join at all, so there is nothing uncertain
	// about it. Reporting it as low confidence would make the whole signal useless:
	// most traffic on a single-vendor hostname would drown out the real ambiguity.
	if in.VendorCount <= 1 {
		return High
	}

	// Tier 1 rests on an exact identifier both vendors reported. Nothing about
	// timing or addressing can undermine that.
	if in.Tier == keys.TierExact {
		return High
	}

	// Tier 2 with genuine ambiguity: a shared address, or several candidates in the
	// window. Either means the platform picked one of multiple plausible partners.
	if in.Ambiguous || in.CandidateCount > 1 {
		return Low
	}

	return Medium
}
