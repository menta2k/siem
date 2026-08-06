package query_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
)

var queryNow = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func testLimits() query.Limits {
	return query.Limits{MaxResultRows: 1000, MaxRangeDays: 90, MaxExecution: 3 * time.Second}
}

// An unbounded scan reads every partition the tenant has ever written. It is rejected
// rather than queued, because a query that cannot finish inside the latency budget
// hurts every other tenant on the cluster while it runs.
func TestMissingTimeRangeIsRejected(t *testing.T) {
	cases := map[string]struct{ from, to time.Time }{
		"both missing": {},
		"no from":      {to: queryNow},
		"no to":        {from: queryNow.Add(-time.Hour)},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := testLimits().Range(tc.from, tc.to, queryNow)
			if err == nil {
				t.Fatal("an unbounded query was accepted")
			}
			if got := mw.AsError(err).Code; got != mw.CodeTimeRangeRequired {
				t.Errorf("code = %q, want %q", got, mw.CodeTimeRangeRequired)
			}
		})
	}
}

func TestRangeBeyondTheCapIsRejected(t *testing.T) {
	limits := testLimits()
	from := queryNow.AddDate(0, 0, -(limits.MaxRangeDays + 1))

	_, err := limits.Range(from, queryNow, queryNow)
	if err == nil {
		t.Fatal("a range past the cap was accepted")
	}
	if got := mw.AsError(err).Code; got != mw.CodeTimeRangeTooLarge {
		t.Errorf("code = %q, want %q", got, mw.CodeTimeRangeTooLarge)
	}
}

func TestRangeExactlyAtTheCapIsAccepted(t *testing.T) {
	limits := testLimits()
	from := queryNow.AddDate(0, 0, -limits.MaxRangeDays)

	if _, err := limits.Range(from, queryNow, queryNow); err != nil {
		t.Errorf("a range exactly at the cap was rejected: %v", err)
	}
}

func TestInvertedRangeIsRejected(t *testing.T) {
	_, err := testLimits().Range(queryNow, queryNow.Add(-time.Hour), queryNow)
	if err == nil {
		t.Fatal("a range ending before it starts was accepted")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
}

// A zero-width range returns nothing and is almost always a UI bug rather than intent.
// Rejecting it says so instead of returning an empty page that looks like "no data".
func TestZeroWidthRangeIsRejected(t *testing.T) {
	if _, err := testLimits().Range(queryNow, queryNow, queryNow); err == nil {
		t.Error("a zero-width range was accepted")
	}
}

// Clock skew on an analyst's browser must not silently truncate their range.
func TestFutureEndIsClampedToNow(t *testing.T) {
	limits := testLimits()
	from := queryNow.Add(-time.Hour)

	got, err := limits.Range(from, queryNow.Add(time.Hour), queryNow)
	if err != nil {
		t.Fatalf("a slightly-future end was rejected: %v", err)
	}
	if got.To.After(queryNow) {
		t.Errorf("To = %v, want it clamped to now (%v)", got.To, queryNow)
	}
}

func TestRangeIsNormalizedToUTC(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}

	got, err := testLimits().Range(
		queryNow.Add(-time.Hour).In(berlin), queryNow.In(berlin), queryNow)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if got.From.Location() != time.UTC || got.To.Location() != time.UTC {
		t.Errorf("range not normalized to UTC: %v..%v", got.From, got.To)
	}
}

func TestLimitIsCapped(t *testing.T) {
	limits := testLimits()

	cases := map[string]struct {
		requested int32
		want      int32
	}{
		"unset falls back to a default": {0, query.DefaultPageSize},
		"negative falls back":           {-5, query.DefaultPageSize},
		"within the cap is kept":        {250, 250},
		"at the cap is kept":            {1000, 1000},
		"beyond the cap is capped":      {50_000, 1000},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := limits.PageSize(tc.requested); got != tc.want {
				t.Errorf("PageSize(%d) = %d, want %d", tc.requested, got, tc.want)
			}
		})
	}
}

// The deadline is what actually stops a runaway query; the SQL-level setting alone
// cannot bound time spent streaming results back.
func TestQueryContextCarriesTheExecutionDeadline(t *testing.T) {
	ctx, cancel := testLimits().WithTimeout(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("no deadline set on the query context")
	}
	if remaining := time.Until(deadline); remaining > 3*time.Second+time.Second {
		t.Errorf("deadline is %v away, want about the max execution time", remaining)
	}
}

// An overrun must surface as QUERY_TIMEOUT, not as an opaque internal error: the
// analyst's next move is to narrow the range, and only a specific code says so.
func TestDeadlineExceededBecomesQueryTimeout(t *testing.T) {
	err := query.TranslateError(context.DeadlineExceeded)
	if err == nil {
		t.Fatal("a deadline overrun was not translated")
	}
	if got := mw.AsError(err).Code; got != mw.CodeQueryTimeout {
		t.Errorf("code = %q, want %q", got, mw.CodeQueryTimeout)
	}
}

// ClickHouse reports its own server-side timeout as error code 159, which arrives as
// a driver error rather than a context error.
func TestClickHouseTimeoutBecomesQueryTimeout(t *testing.T) {
	err := query.TranslateError(errors.New(
		"clickhouse query: code: 159, message: Timeout exceeded: elapsed 3.1 seconds"))
	if got := mw.AsError(err).Code; got != mw.CodeQueryTimeout {
		t.Errorf("code = %q, want %q", got, mw.CodeQueryTimeout)
	}
}

func TestUnrelatedErrorsAreNotDisguisedAsTimeouts(t *testing.T) {
	err := query.TranslateError(errors.New("connection refused"))
	if got := mw.AsError(err).Code; got == mw.CodeQueryTimeout {
		t.Error("an unrelated failure was reported as a query timeout, which would send " +
			"an analyst to narrow their range over a broken connection")
	}
}

func TestNilErrorTranslatesToNil(t *testing.T) {
	if err := query.TranslateError(nil); err != nil {
		t.Errorf("TranslateError(nil) = %v, want nil", err)
	}
}

// A misconfigured deployment must not silently disable the bounds.
func TestZeroLimitsFallBackToDefaults(t *testing.T) {
	var empty query.Limits

	if got := empty.PageSize(0); got <= 0 {
		t.Errorf("PageSize = %d, want a positive default", got)
	}
	if _, err := empty.Range(queryNow.AddDate(0, 0, -3650), queryNow, queryNow); err == nil {
		t.Error("a ten-year range was accepted with zero-valued limits")
	}
}
