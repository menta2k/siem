package query_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
)

// codeOf reads the stable API code a translated error carries.
func codeOf(t *testing.T, err error) string {
	t.Helper()

	var apiErr *mw.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not an API error: %v", err)
	}
	return apiErr.Code
}

// THE BUG THIS CATCHES, reported as intermittent INTERNAL errors on search. Every read
// path translates TWICE — once in the repository, once in the service above it. The
// second call could not recognise the first call's own output, because a QueryTimeout's
// message contains neither "code: 159" nor "TIMEOUT_EXCEEDED", so it wrapped it as
// INTERNAL. The user got "an internal error occurred" instead of "narrow the time range
// or add filters".
func TestTranslatingTwiceKeepsTheFirstAnswer(t *testing.T) {
	once := query.TranslateError(fmt.Errorf("clickhouse: code: 159, TIMEOUT_EXCEEDED"))
	if got := codeOf(t, once); got != "QUERY_TIMEOUT" {
		t.Fatalf("first translation = %s, want QUERY_TIMEOUT", got)
	}

	twice := query.TranslateError(once)
	if got := codeOf(t, twice); got != "QUERY_TIMEOUT" {
		t.Errorf("second translation = %s, want QUERY_TIMEOUT — it was re-wrapped", got)
	}
}

// The same property for every classification, since the double call is on all of them.
func TestTranslationIsIdempotent(t *testing.T) {
	cases := map[string]error{
		"timeout":   fmt.Errorf("code: 159"),
		"not found": mw.NotFound("event"),
		"conflict":  mw.Conflict("already exists"),
		"internal":  mw.Internal().WithCause(errors.New("boom")),
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			once := query.TranslateError(input)
			twice := query.TranslateError(once)

			if codeOf(t, once) != codeOf(t, twice) {
				t.Errorf("code changed on re-translation: %s then %s",
					codeOf(t, once), codeOf(t, twice))
			}
		})
	}
}

// THE OTHER HALF OF THE REPORT. The driver's read deadline expiring arrived as
// "read tcp ...: i/o timeout" and was classed INTERNAL, so an ordinary too-wide search
// looked like a platform fault — in the UI and in the error budget. It is the same
// event as the server-side limit, seen from the client end.
func TestADriverReadDeadlineIsAQueryTimeout(t *testing.T) {
	netErr := &net.OpError{
		Op: "read", Net: "tcp",
		Err: os.ErrDeadlineExceeded,
	}
	wrapped := fmt.Errorf(
		"query processing: failed to read packet from 172.18.0.5:9000 (conn_id=12): %w", netErr)

	if got := codeOf(t, query.TranslateError(wrapped)); got != "QUERY_TIMEOUT" {
		t.Errorf("code = %s, want QUERY_TIMEOUT", got)
	}
}

// A genuine fault must still read as one. If everything became a timeout, the message
// would stop meaning anything and a real outage would be reported as a slow query.
func TestARealFailureIsStillInternal(t *testing.T) {
	err := query.TranslateError(errors.New("clickhouse: code: 241, MEMORY_LIMIT_EXCEEDED"))

	if got := codeOf(t, err); got != "INTERNAL" {
		t.Errorf("code = %s, want INTERNAL", got)
	}
}

// A closed browser tab is not a failure, and counting it as one fills the error budget
// with users navigating away.
func TestAClientHangUpIsNotInternal(t *testing.T) {
	err := query.TranslateError(fmt.Errorf("read: %w", context.Canceled))

	if got := codeOf(t, err); got == "INTERNAL" {
		t.Error("a cancelled request was reported as an internal error")
	}
}

func TestTranslateNilIsNil(t *testing.T) {
	if err := query.TranslateError(nil); err != nil {
		t.Errorf("TranslateError(nil) = %v, want nil", err)
	}
}
