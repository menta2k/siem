package receiver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/menta2k/siem/internal/secrets"
)

// captureLogger keeps what was logged, so a test can assert that a failure was written
// down rather than only counted.
type captureLogger struct {
	mu    sync.Mutex
	lines strings.Builder
}

func (l *captureLogger) write(level, msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines.WriteString(level + " " + msg)
	for _, v := range kv {
		l.lines.WriteString(" " + fmt.Sprint(v))
	}
	l.lines.WriteString("\n")
}

func (l *captureLogger) Debug(_ context.Context, msg string, kv ...any) {
	l.write("debug", msg, kv...)
}
func (l *captureLogger) Info(_ context.Context, msg string, kv ...any) {
	l.write("info", msg, kv...)
}
func (l *captureLogger) Warn(_ context.Context, msg string, kv ...any) {
	l.write("warn", msg, kv...)
}
func (l *captureLogger) Error(_ context.Context, msg string, kv ...any) {
	l.write("error", msg, kv...)
}

func (l *captureLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.String()
}

// sawInvalidCredential reports whether any sample marked the credential as failing.
func (r *recordedHealth) sawInvalidCredential() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sample := range r.samples {
		if !sample.CredentialValid {
			return true
		}
	}
	return false
}

// What a lost secret store looks like from the delivery path.
//
// The platform once spent two hours rejecting every delivery from every feed because its
// cache had been emptied and the credentials were gone. Two things made that two hours
// instead of two minutes: the answer said only "500", which reads as "the sender did
// something wrong", and nothing was written to the log at all.

// THE DISTINCTION THAT WAS MISSING. A wrong token is the sender's problem and a missing
// stored secret is this platform's; they looked identical, and they lead to opposite
// fixes — reconfigure the vendor, or restore the store.
func TestAMissingStoredSecretIsNotReportedAsABadToken(t *testing.T) {
	h := newHarness(t)
	h.secrets.err = secrets.ErrNotFound

	rec := h.deliver(t, `{"RayID":"a1","ClientIP":"1.2.3.4"}`)

	if rec.Code == 401 {
		t.Error("a secret this platform lost was blamed on the sender's credential")
	}
	if rec.Code != 503 {
		t.Errorf("status = %d, want 503: the platform cannot answer right now, and a "+
			"sender that honours it retries instead of dropping", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "FEED_CREDENTIAL_UNAVAILABLE") {
		t.Errorf("body = %s, want a code that names the fault", rec.Body.String())
	}
}

// A token that simply does not match is still the sender's problem, and still a 401.
func TestAWrongTokenIsStillRejectedAsOne(t *testing.T) {
	h := newHarness(t)

	rec := h.deliver(t, `{"RayID":"a1"}`, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer not-the-token")
	})

	if rec.Code != 401 {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "UNAVAILABLE") {
		t.Error("a wrong token was reported as the platform's fault")
	}
}

// The failure has to be VISIBLE. A counter on a dashboard nobody was watching is what the
// platform had; the log line is what an operator finds when a feed goes quiet.
func TestARefusedCredentialIsLogged(t *testing.T) {
	h := newHarness(t)
	h.secrets.err = secrets.ErrNotFound

	h.deliver(t, `{"RayID":"a1"}`)

	logged := h.log.String()
	if !strings.Contains(logged, "credential not accepted") {
		t.Errorf("log = %q, want the refusal written down", logged)
	}
	if !strings.Contains(logged, h.feedID.String()) {
		t.Error("the log does not name the feed, so it cannot be acted on")
	}
}

// The health counter still has to fall, since that is what the console reads.
func TestARefusedCredentialStillMarksTheFeedUnhealthy(t *testing.T) {
	h := newHarness(t)
	h.secrets.err = secrets.ErrNotFound

	h.deliver(t, `{"RayID":"a1"}`)

	if !h.health.sawInvalidCredential() {
		t.Error("the feed was not marked as having a credential problem")
	}
}
