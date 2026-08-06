//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/alerting/rule"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/test/support"
)

var alertBase = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

// webhookEndpoint is a receiver that records what it was sent.
//
// Named to avoid shadowing the ingest `receiver` package, which this suite also uses.
type webhookEndpoint struct {
	mu sync.Mutex

	server   *httptest.Server
	requests []receivedRequest
	// failFirst rejects this many deliveries before succeeding, to exercise retry.
	failFirst int
	// alwaysFail models an endpoint that is permanently broken.
	alwaysFail bool
	secret     string
}

type receivedRequest struct {
	body      []byte
	signature string
	timestamp string
}

func newReceiver(t *testing.T, secret string) *webhookEndpoint {
	t.Helper()

	r := &webhookEndpoint{secret: secret}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))

		r.mu.Lock()
		r.requests = append(r.requests, receivedRequest{
			body:      body,
			signature: req.Header.Get("X-Siem-Signature"),
			timestamp: req.Header.Get("X-Siem-Timestamp"),
		})
		count, failFirst, always := len(r.requests), r.failFirst, r.alwaysFail
		r.mu.Unlock()

		if always || count <= failFirst {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *webhookEndpoint) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func (r *webhookEndpoint) last() (receivedRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) == 0 {
		return receivedRequest{}, false
	}
	return r.requests[len(r.requests)-1], true
}

// alertRig is the alerting pipeline wired to real ClickHouse and Redis.
type alertRig struct {
	fixture *support.Fixture
	repo    *chdata.AlertingRepo
	worker  *alerting.Worker
	secrets secrets.Store
	ctx     context.Context
	tenant  chdata.Tenant
}

func newAlertRig(t *testing.T, name string, consoleURL string) *alertRig {
	return newAlertRigWith(t, name, consoleURL, alerting.AllowPrivateTargets())
}

// newStrictAlertRig builds the rig with production SSRF rules, so the refusal test
// exercises the real default rather than the relaxed one every other test needs.
func newStrictAlertRig(t *testing.T, name, consoleURL string) *alertRig {
	return newAlertRigWith(t, name, consoleURL)
}

func newAlertRigWith(
	t *testing.T, name, consoleURL string, opts ...alerting.Option,
) *alertRig {
	t.Helper()

	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, name)

	locker := chdata.NewLocker(f.Redis)
	repo := chdata.NewAlertingRepo(f.ClickHouse, locker)
	secretStore := secrets.NewRedisStore(f.Redis)

	worker := alerting.NewWorker(
		repo,
		alerting.NewEvaluator(alerting.NewRepoStore(repo)),
		alerting.NewCooldown(f.Redis),
		alerting.NewWebhook(secretStore, consoleURL, opts...),
		mw.NewLogger("error", "json"),
	)

	return &alertRig{
		fixture: f, repo: repo, worker: worker,
		secrets: secretStore, ctx: ctx, tenant: tenant,
	}
}

func (r *alertRig) createRule(t *testing.T, webhookURL, secret string) chdata.AlertRule {
	t.Helper()

	condition := rule.Condition{
		Aggregate: rule.AggregateCount, Comparator: rule.ComparatorGreaterThan,
		Threshold: 0, WindowSeconds: 300, CooldownSeconds: 900,
	}
	encoded, err := condition.Encode()
	if err != nil {
		t.Fatalf("encode condition: %v", err)
	}

	secretRef := ""
	if secret != "" {
		if secretRef, err = r.secrets.Put(r.ctx, "alert-webhook", secret); err != nil {
			t.Fatalf("store webhook secret: %v", err)
		}
	}

	created, err := r.repo.CreateRule(r.ctx, chdata.AlertRule{
		Name: "delivery test", Enabled: true, Severity: chdata.SeverityHigh,
		Condition: encoded, WindowSeconds: 300, CooldownSeconds: 900,
		WebhookURL: webhookURL, WebhookSecretRef: secretRef,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	r.fixture.Sync(t, "alert_rules")
	return created
}

func (r *alertRig) fireAlert(t *testing.T, ruleID uuid.UUID) chdata.Alert {
	t.Helper()

	alert, err := r.repo.InsertAlert(r.ctx, chdata.Alert{
		TenantID: r.tenant.ID, RuleID: ruleID, FiredAt: alertBase,
		Severity: chdata.SeverityHigh, State: chdata.AlertStateNew,
		ObservedValue: 42, Threshold: 10,
		EvidenceCorrelationIDs: []uuid.UUID{uuid.New(), uuid.New()},
		NotifyStatus:           chdata.NotifyPending,
	})
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	r.fixture.Sync(t, "alerts")
	return alert
}

func (r *alertRig) reload(t *testing.T, alertID uuid.UUID) chdata.Alert {
	t.Helper()

	r.fixture.Sync(t, "alerts")
	alert, err := r.repo.GetAlert(r.ctx, alertID)
	if err != nil {
		t.Fatalf("reload alert: %v", err)
	}
	return alert
}

// ---------------------------------------------------------------- the tests

func TestSuccessfulDeliveryIsRecorded(t *testing.T) {
	endpoint := newReceiver(t, "")
	rig := newAlertRig(t, "alert-delivery-ok", "https://console.example.com")

	created := rig.createRule(t, endpoint.server.URL, "")
	alert := rig.fireAlert(t, created.ID)

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	if endpoint.count() != 1 {
		t.Fatalf("%d deliveries, want 1", endpoint.count())
	}

	updated := rig.reload(t, alert.ID)
	if updated.NotifyStatus != chdata.NotifyDelivered {
		t.Errorf("notify_status = %q, want delivered", updated.NotifyStatus)
	}
}

// The payload carries deep links so the first click from a chat message lands on the
// evidence rather than on a dashboard (SC-006).
func TestPayloadCarriesEvidenceLinks(t *testing.T) {
	endpoint := newReceiver(t, "")
	rig := newAlertRig(t, "alert-evidence", "https://console.example.com")

	created := rig.createRule(t, endpoint.server.URL, "")
	alert := rig.fireAlert(t, created.ID)

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	last, ok := endpoint.last()
	if !ok {
		t.Fatal("nothing was delivered")
	}

	var payload alerting.Payload
	if err := json.Unmarshal(last.body, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if payload.AlertID != alert.ID.String() {
		t.Errorf("alert_id = %q, want %q", payload.AlertID, alert.ID)
	}
	if len(payload.EvidenceURLs) != 2 {
		t.Fatalf("%d evidence links, want 2", len(payload.EvidenceURLs))
	}
	want := alerting.EvidenceURL("https://console.example.com",
		alert.EvidenceCorrelationIDs[0])
	if payload.EvidenceURLs[0] != want {
		t.Errorf("evidence link = %q, want %q", payload.EvidenceURLs[0], want)
	}
}

// The signature covers the timestamp as well as the body, so a captured delivery
// cannot be replayed indefinitely.
func TestDeliveryIsSignedOverBodyAndTimestamp(t *testing.T) {
	const secret = "hunter2-hunter2-hunter2"
	endpoint := newReceiver(t, secret)
	rig := newAlertRig(t, "alert-signing", "https://console.example.com")

	created := rig.createRule(t, endpoint.server.URL, secret)
	rig.fireAlert(t, created.ID)

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	last, ok := endpoint.last()
	if !ok {
		t.Fatal("nothing was delivered")
	}
	if last.signature == "" || last.timestamp == "" {
		t.Fatal("the delivery was unsigned")
	}
	if !alerting.Verify(secret, last.timestamp, last.body, last.signature) {
		t.Error("the signature does not verify with the configured secret")
	}
	if alerting.Verify("a-different-secret", last.timestamp, last.body, last.signature) {
		t.Error("the signature verified under the wrong secret")
	}
	// A signature over the body alone would still verify with a different timestamp.
	if alerting.Verify(secret, "1", last.body, last.signature) {
		t.Error("the signature does not cover the timestamp, so it can be replayed")
	}
}

// A transient failure must be retried, and the attempt count must be visible.
func TestTransientFailureIsRetried(t *testing.T) {
	endpoint := newReceiver(t, "")
	endpoint.failFirst = 1

	rig := newAlertRig(t, "alert-retry", "https://console.example.com")
	created := rig.createRule(t, endpoint.server.URL, "")
	alert := rig.fireAlert(t, created.ID)

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	afterFirst := rig.reload(t, alert.ID)
	if afterFirst.NotifyStatus != chdata.NotifyPending {
		t.Fatalf("notify_status = %q after a transient failure, want pending",
			afterFirst.NotifyStatus)
	}
	if afterFirst.NotifyAttempts != 1 {
		t.Errorf("notify_attempts = %d, want 1", afterFirst.NotifyAttempts)
	}
	if afterFirst.NotifyLastError == "" {
		t.Error("the failure reason was not recorded, so the console cannot show it")
	}
}

// The backoff is real: a retry must not be attempted before its delay has elapsed, or
// a broken endpoint is hammered as fast as the worker loops.
func TestRetryRespectsTheBackoff(t *testing.T) {
	endpoint := newReceiver(t, "")
	endpoint.alwaysFail = true

	rig := newAlertRig(t, "alert-backoff", "https://console.example.com")
	created := rig.createRule(t, endpoint.server.URL, "")

	// Fired now, so the backoff after the first attempt has definitely not elapsed.
	alert, err := rig.repo.InsertAlert(rig.ctx, chdata.Alert{
		TenantID: rig.tenant.ID, RuleID: created.ID, FiredAt: time.Now().UTC(),
		Severity: chdata.SeverityHigh, State: chdata.AlertStateNew,
		ObservedValue: 42, Threshold: 10, NotifyStatus: chdata.NotifyPending,
	})
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	rig.fixture.Sync(t, "alerts")

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	first := endpoint.count()

	// An immediate second pass must be skipped by the backoff.
	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	if endpoint.count() != first {
		t.Errorf("%d deliveries after an immediate retry, want %d — the backoff was ignored",
			endpoint.count(), first)
	}
	_ = alert
}

// A permanently failing webhook must still leave a PERSISTED alert marked failed. The
// alert's existence is the guarantee; the notification is best effort on top of it.
func TestAPermanentlyFailingWebhookStillLeavesTheAlert(t *testing.T) {
	endpoint := newReceiver(t, "")
	endpoint.alwaysFail = true

	rig := newAlertRig(t, "alert-permafail", "https://console.example.com")
	created := rig.createRule(t, endpoint.server.URL, "")

	// Already at the last attempt, so this pass exhausts the retries.
	alert, err := rig.repo.InsertAlert(rig.ctx, chdata.Alert{
		TenantID: rig.tenant.ID, RuleID: created.ID, FiredAt: alertBase,
		Severity: chdata.SeverityHigh, State: chdata.AlertStateNew,
		ObservedValue: 42, Threshold: 10,
		NotifyStatus:   chdata.NotifyPending,
		NotifyAttempts: alerting.MaxAttempts - 1,
	})
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	rig.fixture.Sync(t, "alerts")

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	final := rig.reload(t, alert.ID)
	if final.NotifyStatus != chdata.NotifyFailed {
		t.Errorf("notify_status = %q, want failed", final.NotifyStatus)
	}
	if final.State != chdata.AlertStateNew {
		t.Errorf("state = %q, want the alert still in the triage queue", final.State)
	}
	if final.NotifyLastError == "" {
		t.Error("no failure reason was recorded")
	}

	// And it must be findable by the operator asking "what did we fail to send".
	failed, err := rig.repo.ListAlerts(rig.ctx, chdata.AlertFilter{
		NotifyStatus: chdata.NotifyFailed, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(failed) != 1 {
		t.Errorf("%d alerts with a failed delivery, want 1", len(failed))
	}
}

// SSRF: a webhook URL is tenant-supplied and the request originates inside the cluster.
func TestInternalWebhookTargetsAreRefused(t *testing.T) {
	rig := newStrictAlertRig(t, "alert-ssrf", "https://console.example.com")

	for _, endpoint := range []string{
		"http://127.0.0.1:8123/",
		"http://localhost:9000/",
		"http://10.0.0.5/hook",
		"http://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
	} {
		created := rig.createRule(t, endpoint, "")
		alert := rig.fireAlert(t, created.ID)

		if err := rig.worker.DeliverPending(rig.ctx); err != nil {
			t.Fatalf("DeliverPending: %v", err)
		}

		final := rig.reload(t, alert.ID)
		if final.NotifyStatus != chdata.NotifyFailed {
			t.Errorf("endpoint %q gave notify_status %q, want failed",
				endpoint, final.NotifyStatus)
		}
	}
}

// A rule with no webhook is not a delivery failure: the alert is visible in the
// console, which is the primary channel.
func TestARuleWithNoWebhookIsNotAFailure(t *testing.T) {
	rig := newAlertRig(t, "alert-nowebhook", "https://console.example.com")

	created := rig.createRule(t, "", "")
	alert := rig.fireAlert(t, created.ID)

	if err := rig.worker.DeliverPending(rig.ctx); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}

	final := rig.reload(t, alert.ID)
	if final.NotifyStatus == chdata.NotifyFailed {
		t.Error("an alert with no webhook configured was marked as a delivery failure")
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	previous := time.Duration(0)
	for attempt := 1; attempt <= alerting.MaxAttempts+3; attempt++ {
		delay := alerting.Backoff(attempt)
		if delay <= 0 {
			t.Fatalf("attempt %d has a non-positive delay", attempt)
		}
		if delay < previous {
			t.Errorf("attempt %d waits %v, less than the previous %v", attempt, delay, previous)
		}
		if delay > alerting.MaxBackoff {
			t.Errorf("attempt %d waits %v, above the cap %v", attempt, delay, alerting.MaxBackoff)
		}
		previous = delay
	}
}
