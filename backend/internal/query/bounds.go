// Package query enforces the bounds that keep search answerable.
//
// Every read of event data is bounded three ways, and all three are load-bearing:
//
//	a mandatory time range   so a query cannot read every partition a tenant owns
//	a result cap             so a response cannot exhaust memory on either end
//	an execution deadline    so one query cannot hold the cluster for everyone else
//
// These are rejections, not truncations. A query that silently returns the first
// slice of an unbounded scan is worse than one that fails: the analyst reads a partial
// answer as a complete one and concludes the attack stopped.
package query

import (
	"context"
	"errors"
	"strings"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
)

// Bounds defaults, used when configuration supplies nothing usable.
//
// A misconfigured deployment must land on something safe rather than on "unlimited":
// a zero-valued Limits struct reads as no bounds at all, which is precisely the state
// this package exists to prevent.
const (
	DefaultPageSize     int32 = 100
	DefaultMaxRows      int32 = 1000
	DefaultMaxRangeDays       = 90
	DefaultMaxExecution       = 3 * time.Second
)

// Limits are the query bounds for a deployment.
type Limits struct {
	// MaxResultRows caps a single page.
	MaxResultRows int32
	// MaxRangeDays caps how wide a time range may be.
	MaxRangeDays int
	// MaxExecution caps wall-clock time for one query.
	MaxExecution time.Duration
}

// DefaultLimits returns the platform defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxResultRows: DefaultMaxRows,
		MaxRangeDays:  DefaultMaxRangeDays,
		MaxExecution:  DefaultMaxExecution,
	}
}

func (l Limits) maxRows() int32 {
	if l.MaxResultRows <= 0 {
		return DefaultMaxRows
	}
	return l.MaxResultRows
}

func (l Limits) maxRangeDays() int {
	if l.MaxRangeDays <= 0 {
		return DefaultMaxRangeDays
	}
	return l.MaxRangeDays
}

// MaxExecutionOrDefault returns the execution cap, substituting the default when unset.
func (l Limits) MaxExecutionOrDefault() time.Duration {
	if l.MaxExecution <= 0 {
		return DefaultMaxExecution
	}
	return l.MaxExecution
}

// TimeRange is a validated, UTC-normalized query window.
type TimeRange struct {
	From time.Time
	To   time.Time
}

// Days is the range width, rounded up, for logging and metrics.
func (r TimeRange) Days() int {
	return int(r.To.Sub(r.From).Hours()/24) + 1
}

// Range validates and normalizes a requested time window.
//
// `now` is a parameter rather than a call to time.Now so the bounds can be tested
// deterministically — a rule about time that can only be checked against the real
// clock is a rule that gets tested loosely or not at all.
func (l Limits) Range(from, to, now time.Time) (TimeRange, error) {
	if from.IsZero() || to.IsZero() {
		return TimeRange{}, mw.TimeRangeRequired()
	}

	from, to = from.UTC(), to.UTC()

	// An end slightly in the future is clock skew on the analyst's machine, not an
	// attempt to read the future. Clamping is friendlier than rejecting, and reading
	// up to "now" is what they meant.
	if to.After(now.UTC()) {
		to = now.UTC()
	}

	if !from.Before(to) {
		return TimeRange{}, mw.ValidationFailed(
			"the time range must start before it ends")
	}

	if to.Sub(from) > time.Duration(l.maxRangeDays())*24*time.Hour {
		return TimeRange{}, mw.TimeRangeTooLarge(l.maxRangeDays())
	}

	return TimeRange{From: from, To: to}, nil
}

// PageSize clamps a requested page size into the allowed band.
//
// Clamped rather than rejected: an oversized page is a client asking for more than the
// platform will give, and returning the maximum with a cursor is a complete answer.
// An oversized time RANGE is different — there the result would be silently partial.
func (l Limits) PageSize(requested int32) int32 {
	switch {
	case requested <= 0:
		return DefaultPageSize
	case requested > l.maxRows():
		return l.maxRows()
	default:
		return requested
	}
}

// WithTimeout derives the query context.
//
// The deadline is the enforcement that actually holds. ClickHouse's own
// max_execution_time bounds the server's work but not the time spent streaming rows
// back, so a query can comply with the setting and still hold a connection open far
// past the budget.
func (l Limits) WithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, l.MaxExecutionOrDefault())
}

// TranslateError converts a storage failure into a stable API error.
//
// The distinction that matters is timeout versus everything else. A timeout tells the
// analyst to narrow their range, which is an action they can take; anything else tells
// them to call an operator. Reporting one as the other sends them to the wrong place.
func TranslateError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.DeadlineExceeded) || isClickHouseTimeout(err) {
		return mw.QueryTimeout()
	}
	if errors.Is(err, context.Canceled) {
		// The client hung up. Nothing failed, and logging it as an internal error
		// would fill the error budget with users closing browser tabs.
		return mw.AsError(err)
	}
	return mw.Internal().WithCause(err)
}

// isClickHouseTimeout matches the server-side execution timeout.
//
// Matched on the error CODE rather than the message text: ClickHouse's wording has
// changed between versions, and a match on prose is a check that silently stops
// working after an upgrade.
func isClickHouseTimeout(err error) bool {
	text := err.Error()
	return strings.Contains(text, "code: 159") ||
		strings.Contains(text, "TIMEOUT_EXCEEDED")
}
