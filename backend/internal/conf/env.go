package conf

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// minSigningKeyLen is the minimum accepted JWT signing key length. 32 bytes is the
// floor for HMAC-SHA256; shorter keys weaken the signature regardless of entropy.
const minSigningKeyLen = 32

// required reads a variable that must be present and non-empty.
func required(key string) (string, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return "", fmt.Errorf("%s is required but not set", key)
	}
	return v, nil
}

// optional reads a variable, falling back to a default when unset or blank.
func optional(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// integer parses an int variable, falling back to a default when unset.
func integer(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q: %w", key, raw, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("%s must not be negative, got %d", key, v)
	}
	return v, nil
}

// integer32 parses a variable that must fit in an int32.
//
// A separate helper because the conversion is where the bug lives: integer() rejects
// negatives but not values above 2^31, and narrowing one of those wraps it to a
// negative number. The result is a limit that reads as "unset" and silently falls back
// to a default the operator did not choose.
func integer32(key string, fallback int32) (int32, error) {
	v, err := integer(key, int(fallback))
	if err != nil {
		return 0, err
	}
	if v > math.MaxInt32 {
		return 0, fmt.Errorf("%s must be at most %d, got %d", key, math.MaxInt32, v)
	}
	// Safe: integer() rejects negatives and the bound above rejects anything larger,
	// so v is within int32 by the time it gets here.
	return int32(v), nil //nolint:gosec // range checked on the two lines above
}

// integer64 parses an int64 variable, falling back to a default when unset.
func integer64(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q: %w", key, raw, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("%s must not be negative, got %d", key, v)
	}
	return v, nil
}

func durationSeconds(key string, fallback int) (time.Duration, error) {
	v, err := integer(key, fallback)
	return time.Duration(v) * time.Second, err
}

func durationMillis(key string, fallback int) (time.Duration, error) {
	v, err := integer(key, fallback)
	return time.Duration(v) * time.Millisecond, err
}

func durationMinutes(key string, fallback int) (time.Duration, error) {
	v, err := integer(key, fallback)
	return time.Duration(v) * time.Minute, err
}

func durationHours(key string, fallback int) (time.Duration, error) {
	v, err := integer(key, fallback)
	return time.Duration(v) * time.Hour, err
}

// splitList parses a comma-separated list, discarding blank entries.
func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
