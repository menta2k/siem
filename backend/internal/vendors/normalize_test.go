package vendors

import (
	"errors"
	"testing"
	"time"
)

// Found by fuzzing: a garbage epoch parsed into year 2223. That is worse than a
// rejection — ClickHouse would create a partition two centuries out, and the event
// would sit in a correlation window that can never match.
func TestParseTimeRejectsImplausibleTimestamps(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"far future seconds", float64(8000000000)},
		{"far future millis", float64(8000000000000)},
		{"far past", float64(1)},
		{"epoch zero", float64(0)},
		{"negative", float64(-1000)},
		{"far future string", "8000000000"},
		{"year 3000 rfc3339", "3000-01-01T00:00:00Z"},
		{"year 1900 rfc3339", "1900-01-01T00:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseTime(tt.value)
			if err == nil {
				t.Fatalf("ParseTime(%v) accepted an implausible timestamp", tt.value)
			}
			if !errors.Is(err, ErrTimestampImplausible) {
				t.Errorf("error = %v, want ErrTimestampImplausible", err)
			}
		})
	}
}

func TestParseTimeAcceptsPlausibleEncodings(t *testing.T) {
	want := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		value any
	}{
		{"rfc3339", "2026-08-06T12:00:00Z"},
		{"rfc3339 nano", "2026-08-06T12:00:00.000000000Z"},
		{"epoch seconds", float64(want.Unix())},
		{"epoch millis", float64(want.UnixMilli())},
		{"epoch micros", float64(want.UnixMicro())},
		{"epoch nanos", float64(want.UnixNano())},
		{"epoch as string", "1786017600"},
		{"space separated", "2026-08-06 12:00:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, original, err := ParseTime(tt.value)
			if err != nil {
				t.Fatalf("ParseTime(%v) error = %v", tt.value, err)
			}
			if !got.Equal(want) {
				t.Errorf("ParseTime(%v) = %v, want %v", tt.value, got, want)
			}
			if original == "" {
				t.Error("the original representation was not preserved")
			}
		})
	}
}

// Two vendors reporting the same URI differently must normalize identically, or
// tier-2 correlation silently fails to join them.
func TestNormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/api/checkout", "/api/checkout"},
		{"/API/Checkout", "/api/checkout"},
		{"/api/checkout/", "/api/checkout"},
		{"/api//checkout", "/api/checkout"},
		{"//api///checkout//", "/api/checkout"},
		{"  /api/checkout  ", "/api/checkout"},
		{"/", "/"},
		{"", "/"},
	}

	for _, tt := range tests {
		if got := NormalizePath(tt.in); got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMostRestrictive(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"block wins over allow", []string{VerdictAllowed, VerdictBlocked}, VerdictBlocked},
		{"block wins over challenge", []string{VerdictChallenged, VerdictBlocked}, VerdictBlocked},
		{"rate limit over challenge",
			[]string{VerdictChallenged, VerdictRateLimited}, VerdictRateLimited},
		{"monitored over allowed", []string{VerdictAllowed, VerdictMonitored}, VerdictMonitored},
		{"unknown never masks a block", []string{VerdictUnknown, VerdictBlocked}, VerdictBlocked},
		{"all allowed", []string{VerdictAllowed, VerdictAllowed}, VerdictAllowed},
		{"empty", nil, VerdictUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MostRestrictive(tt.in...); got != tt.want {
				t.Errorf("MostRestrictive(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSplitURI(t *testing.T) {
	tests := []struct{ in, path, query string }{
		{"/api/checkout?step=2", "/api/checkout", "step=2"},
		{"/api/checkout", "/api/checkout", ""},
		{"/?a=1&b=2", "/", "a=1&b=2"},
		{"", "", ""},
	}
	for _, tt := range tests {
		path, query := SplitURI(tt.in)
		if path != tt.path || query != tt.query {
			t.Errorf("SplitURI(%q) = (%q, %q), want (%q, %q)", tt.in, path, query, tt.path, tt.query)
		}
	}
}
