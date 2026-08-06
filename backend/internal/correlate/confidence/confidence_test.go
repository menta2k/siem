package confidence_test

import (
	"testing"

	"github.com/menta2k/siem/internal/correlate/confidence"
	"github.com/menta2k/siem/internal/correlate/keys"
)

// The rule the whole SC-004 budget rests on: an ambiguous join is PUBLISHED as
// ambiguous, not suppressed and not asserted.
func TestScoring(t *testing.T) {
	cases := map[string]struct {
		in   confidence.Input
		want confidence.Level
	}{
		"tier 1 is certain": {
			in:   confidence.Input{Tier: keys.TierExact, VendorCount: 2, CandidateCount: 1},
			want: confidence.High,
		},
		"clean tier 2 is probable": {
			in:   confidence.Input{Tier: keys.TierHeuristic, VendorCount: 2, CandidateCount: 1},
			want: confidence.Medium,
		},
		"a shared address degrades it": {
			in: confidence.Input{
				Tier: keys.TierHeuristic, VendorCount: 2, CandidateCount: 1, Ambiguous: true,
			},
			want: confidence.Low,
		},
		"competing candidates degrade it": {
			in:   confidence.Input{Tier: keys.TierHeuristic, VendorCount: 2, CandidateCount: 3},
			want: confidence.Low,
		},
		// A single-vendor record involved no join at all, so nothing about it is
		// uncertain. Reporting it as low would swamp the signal on single-vendor
		// hostnames until it was worthless.
		"single vendor is not a join": {
			in:   confidence.Input{Tier: keys.TierHeuristic, VendorCount: 1, CandidateCount: 1},
			want: confidence.High,
		},
		"single vendor on a shared address is still not a join": {
			in: confidence.Input{
				Tier: keys.TierHeuristic, VendorCount: 1, CandidateCount: 1, Ambiguous: true,
			},
			want: confidence.High,
		},
		"an unjoinable event is not uncertain either": {
			in:   confidence.Input{Tier: keys.TierNone, VendorCount: 1},
			want: confidence.High,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := confidence.Score(tc.in); got != tc.want {
				t.Errorf("Score(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// An exact identifier cannot be undermined by timing or addressing, so ambiguity flags
// must not drag a tier-1 join down.
func TestTierOneIgnoresHeuristicAmbiguity(t *testing.T) {
	got := confidence.Score(confidence.Input{
		Tier: keys.TierExact, VendorCount: 2, CandidateCount: 5, Ambiguous: true,
	})
	if got != confidence.High {
		t.Errorf("Score = %q, want high — a shared request id is not made uncertain by "+
			"a crowded time window", got)
	}
}
