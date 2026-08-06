package vendors

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// restrictiveness orders verdicts from most to least restrictive. The combined
// outcome of a correlated request is the most restrictive verdict any vendor reached.
var restrictiveness = map[string]int{
	VerdictBlocked:     5,
	VerdictRateLimited: 4,
	VerdictChallenged:  3,
	VerdictMonitored:   2,
	VerdictAllowed:     1,
	VerdictUnknown:     0,
}

// Restrictiveness returns a verdict's rank. Unknown verdicts rank lowest so they
// never mask a real block.
func Restrictiveness(verdict string) int { return restrictiveness[verdict] }

// MostRestrictive returns the strongest verdict among those given.
func MostRestrictive(verdicts ...string) string {
	best := VerdictUnknown
	for _, v := range verdicts {
		if restrictiveness[v] > restrictiveness[best] {
			best = v
		}
	}
	return best
}

// ValidVerdict reports whether a verdict is one of the six defined values.
func ValidVerdict(v string) bool {
	_, ok := restrictiveness[v]
	return ok
}

// Absolute plausibility bounds for an event timestamp.
//
// These are deliberately absolute rather than relative to now: adapters must stay
// pure and deterministic, so they cannot consult a clock. The tighter, now-relative
// window (rejecting anything older than the retention period or in the future) is
// enforced by the normalization worker, which legitimately knows the time.
//
// Without this bound a garbage epoch parses into an absurd year, which is worse than
// a rejection: ClickHouse would create a partition centuries out, and the event would
// sit in a correlation window that can never match. Found by fuzzing.
var (
	minPlausibleTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	maxPlausibleTime = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// ErrTimestampImplausible marks a timestamp outside the absolute bounds.
var ErrTimestampImplausible = errors.New("timestamp is outside the plausible range")

// checkPlausible rejects timestamps no real log line could carry.
func checkPlausible(t time.Time, original string) (time.Time, string, error) {
	if t.Before(minPlausibleTime) || t.After(maxPlausibleTime) {
		return time.Time{}, original,
			fmt.Errorf("%w: %s", ErrTimestampImplausible, t.Format(time.RFC3339))
	}
	return t, original, nil
}

// ParseTime accepts the timestamp encodings the three vendors use and returns UTC.
//
// Cloudflare emits RFC3339 or epoch nanoseconds depending on job configuration, F5
// emits a syslog-style local timestamp, and DataDome emits epoch milliseconds. All
// three appear in the wild, so all three are handled rather than assumed away.
func ParseTime(value any) (time.Time, string, error) {
	switch v := value.(type) {
	case string:
		return parseTimeString(v)
	case float64:
		// JSON numbers decode as float64. The magnitude identifies the unit.
		return checkPlausible(parseEpoch(int64(v)), strconv.FormatFloat(v, 'f', -1, 64))
	case int64:
		return checkPlausible(parseEpoch(v), strconv.FormatInt(v, 10))
	case json_Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, v.String(), fmt.Errorf("timestamp %q is not an integer: %w", v, err)
		}
		return checkPlausible(parseEpoch(n), v.String())
	case nil:
		return time.Time{}, "", fmt.Errorf("timestamp is absent")
	default:
		return time.Time{}, fmt.Sprint(v), fmt.Errorf("timestamp has unsupported type %T", value)
	}
}

// timeLayouts are tried in order. RFC3339 variants first, since two of three vendors
// use them.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05",
	"Jan 2 15:04:05",       // syslog, no year
	"Jan  2 15:04:05",      // syslog, single-digit day is space-padded
	"Jan 02 2006 15:04:05", // F5 CEF
}

func parseTimeString(v string) (time.Time, string, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return time.Time{}, v, fmt.Errorf("timestamp is empty")
	}

	for _, layout := range timeLayouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			// A syslog timestamp carries no year. Assuming the current year is the
			// only option, and it is recorded here so the ambiguity is visible.
			if parsed.Year() == 0 {
				parsed = parsed.AddDate(time.Now().UTC().Year(), 0, 0)
			}
			return checkPlausible(parsed.UTC(), v)
		}
	}

	// Some vendors emit an epoch as a quoted string.
	if n, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return checkPlausible(parseEpoch(n), v)
	}

	return time.Time{}, v, fmt.Errorf("timestamp %q matches no known layout", v)
}

// parseEpoch infers the unit from magnitude. The thresholds distinguish seconds,
// milliseconds, microseconds, and nanoseconds for any plausible modern timestamp.
func parseEpoch(n int64) time.Time {
	switch {
	case n > 1e18: // nanoseconds
		return time.Unix(0, n).UTC()
	case n > 1e15: // microseconds
		return time.Unix(0, n*1e3).UTC()
	case n > 1e12: // milliseconds
		return time.Unix(0, n*1e6).UTC()
	default: // seconds
		return time.Unix(n, 0).UTC()
	}
}

// json_Number mirrors encoding/json.Number without importing it into the type switch
// signature, so callers may pass either representation.
type json_Number interface {
	Int64() (int64, error)
	String() string
}

// ParseIP accepts an address, optionally with a port, and returns nil when absent.
func ParseIP(value string) net.IP {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip
	}
	// F5 sometimes reports "ip:port".
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// SplitURI separates a request target into its path and query components.
//
// Splitting here rather than at query time means the stored path is directly
// comparable across vendors, which is what tier-2 correlation keys on.
func SplitURI(uri string) (path, query string) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return "", ""
	}
	path, query, _ = strings.Cut(uri, "?")
	return path, query
}

// NormalizePath makes paths comparable across vendors, which report the same URI
// differently: lowercase, collapse repeated slashes, and strip a trailing slash.
//
// This is the single most correctness-sensitive helper for tier-2 correlation — if
// two vendors' paths do not normalize identically, the join silently fails.
func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}
	lowered := strings.ToLower(strings.TrimSpace(path))

	var b strings.Builder
	b.Grow(len(lowered))
	var lastWasSlash bool
	for _, r := range lowered {
		if r == '/' {
			if lastWasSlash {
				continue
			}
			lastWasSlash = true
		} else {
			lastWasSlash = false
		}
		b.WriteRune(r)
	}

	cleaned := b.String()
	if len(cleaned) > 1 {
		cleaned = strings.TrimSuffix(cleaned, "/")
	}
	if cleaned == "" {
		return "/"
	}
	return cleaned
}

// ToStatus converts a vendor's status field to a bounded HTTP status code.
func ToStatus(value any) uint16 {
	switch v := value.(type) {
	case float64:
		if v < 0 || v > 599 {
			return 0
		}
		return uint16(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 || n > 599 {
			return 0
		}
		return uint16(n) //nolint:gosec // bounded above
	default:
		return 0
	}
}

// AsString renders a decoded JSON value as a string without panicking on any type.
func AsString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// AsFloat32 extracts a score, reporting whether one was present.
func AsFloat32(value any) (float32, bool) {
	switch v := value.(type) {
	case float64:
		return float32(v), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 32)
		if err != nil {
			return 0, false
		}
		return float32(f), true
	default:
		return 0, false
	}
}

// AsUint32 extracts an ASN or similar identifier.
func AsUint32(value any) uint32 {
	switch v := value.(type) {
	case float64:
		if v < 0 || v > 4294967295 {
			return 0
		}
		return uint32(v)
	case string:
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(v), "AS"), 10, 32)
		if err != nil {
			return 0
		}
		return uint32(n)
	default:
		return 0
	}
}

// AsStringSlice extracts a list field, tolerating a single value in place of a list.
func AsStringSlice(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := AsString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		// Some vendors emit a delimited string where a list is expected.
		if strings.ContainsAny(v, ",;") {
			parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' })
			out := make([]string, 0, len(parts))
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					out = append(out, trimmed)
				}
			}
			return out
		}
		return []string{v}
	default:
		return []string{AsString(v)}
	}
}
