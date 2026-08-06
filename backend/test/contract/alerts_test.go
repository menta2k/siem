//go:build contract

package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/audit"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/internal/tenancy"
)

var (
	alertNow         = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	contractTenantID = uuid.MustParse("00000000-0000-4000-8000-0000000000c1")
)

// tenantContext scopes a context, which a preview needs: the dry run measures the
// caller's data and cannot run without knowing whose.
func tenantContext(t *testing.T) context.Context {
	t.Helper()
	return tenancy.WithTenant(context.Background(),
		tenancy.Tenant{ID: contractTenantID, Name: "contract"})
}

// stubAlerting records what it was asked to store, so the tests assert on the service's
// actual writes rather than only on its responses.
type stubAlerting struct {
	rules  map[uuid.UUID]chdata.AlertRule
	alerts map[uuid.UUID]chdata.Alert
	err    error
}

func newStubAlerting() *stubAlerting {
	return &stubAlerting{
		rules:  map[uuid.UUID]chdata.AlertRule{},
		alerts: map[uuid.UUID]chdata.Alert{},
	}
}

func (s *stubAlerting) ListRules(context.Context) ([]chdata.AlertRule, error) {
	out := make([]chdata.AlertRule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	return out, s.err
}

func (s *stubAlerting) GetRule(_ context.Context, id uuid.UUID) (chdata.AlertRule, error) {
	r, ok := s.rules[id]
	if !ok {
		return chdata.AlertRule{}, chdata.ErrNotFound
	}
	return r, nil
}

func (s *stubAlerting) CreateRule(
	_ context.Context, r chdata.AlertRule,
) (chdata.AlertRule, error) {
	if s.err != nil {
		return chdata.AlertRule{}, s.err
	}
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	r.CreatedAt, r.UpdatedAt, r.Version = alertNow, alertNow, 1
	s.rules[r.ID] = r
	return r, nil
}

func (s *stubAlerting) UpdateRule(
	_ context.Context, id uuid.UUID, mutate func(chdata.AlertRule) chdata.AlertRule,
) (chdata.AlertRule, error) {
	current, ok := s.rules[id]
	if !ok {
		return chdata.AlertRule{}, chdata.ErrNotFound
	}
	updated := mutate(current)
	updated.Version = current.Version + 1
	s.rules[id] = updated
	return updated, nil
}

func (s *stubAlerting) ListAlerts(
	_ context.Context, _ chdata.AlertFilter,
) ([]chdata.Alert, error) {
	out := make([]chdata.Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		out = append(out, a)
	}
	return out, s.err
}

func (s *stubAlerting) GetAlert(_ context.Context, id uuid.UUID) (chdata.Alert, error) {
	a, ok := s.alerts[id]
	if !ok {
		return chdata.Alert{}, chdata.ErrNotFound
	}
	return a, nil
}

func (s *stubAlerting) UpdateAlert(
	_ context.Context, id uuid.UUID, mutate func(chdata.Alert) chdata.Alert,
) (chdata.Alert, error) {
	current, ok := s.alerts[id]
	if !ok {
		return chdata.Alert{}, chdata.ErrNotFound
	}
	updated := mutate(current)
	updated.Version = current.Version + 1
	s.alerts[id] = updated
	return updated, nil
}

// stubPreviewer returns fixed measurements for a dry run.
type stubPreviewer struct {
	results []alerting.Result
	err     error
}

func (s stubPreviewer) Evaluate(
	context.Context, chdata.AlertRule, alerting.Window,
) ([]alerting.Result, error) {
	return s.results, s.err
}

func newAlertsService(
	t *testing.T, store *stubAlerting, previewer stubPreviewer,
) (*service.AlertsService, *stubAudit) {
	t.Helper()
	auditLog := &stubAudit{}
	return service.NewAlertsService(
		store, previewer, secrets.NewMemoryStore(), auditLog), auditLog
}

func validRuleCondition() *pb.RuleCondition {
	return &pb.RuleCondition{
		Aggregate:       pb.RuleAggregate_RULE_AGGREGATE_COUNT,
		Comparator:      pb.RuleComparator_RULE_COMPARATOR_GT,
		Threshold:       10,
		WindowSeconds:   300,
		CooldownSeconds: 900,
	}
}

// ---------------------------------------------------------------- contract

func TestAlertEndpointsArePublished(t *testing.T) {
	spec := loadGeneratedSpec(t)

	cases := map[string]map[string]string{
		"/api/v1/alert-rules": {
			"get": "Alerts_ListAlertRules", "post": "Alerts_CreateAlertRule",
		},
		"/api/v1/alert-rules/{ruleId}": {
			"patch": "Alerts_UpdateAlertRule", "delete": "Alerts_DeleteAlertRule",
		},
		"/api/v1/alert-rules/{ruleId}/preview": {"post": "Alerts_PreviewAlertRule"},
		"/api/v1/alerts":                       {"get": "Alerts_ListAlerts"},
		"/api/v1/alerts/{alertId}":             {"get": "Alerts_GetAlert"},
		"/api/v1/alerts/{alertId}/acknowledge": {"post": "Alerts_AcknowledgeAlert"},
		"/api/v1/alerts/{alertId}/resolve":     {"post": "Alerts_ResolveAlert"},
	}

	for path, methods := range cases {
		for method, operationID := range methods {
			operation, ok := spec.Paths[path][method]
			if !ok {
				t.Errorf("%s %s is not in the generated contract", method, path)
				continue
			}
			if operation.OperationID != operationID {
				t.Errorf("%s %s operationId = %q, want %q",
					method, path, operation.OperationID, operationID)
			}
		}
	}
}

// The signing secret must never leave the platform. Only whether one is configured.
func TestTheWebhookSecretIsNeverReturned(t *testing.T) {
	const secret = "super-secret-signing-key"
	store := newStubAlerting()
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	created, err := svc.CreateAlertRule(context.Background(), &pb.CreateAlertRuleRequest{
		Name: "disagreement spike", Severity: pb.Severity_SEVERITY_HIGH,
		Condition: validRuleCondition(), Enabled: true,
		WebhookUrl: "https://hooks.example.com/siem", WebhookSecret: secret,
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}

	body := encode(t, created)
	for key, value := range body {
		if rendered, ok := value.(string); ok && rendered == secret {
			t.Fatalf("the signing secret was returned in field %q", key)
		}
	}
	if !created.GetWebhookSigningConfigured() {
		t.Error("signing was configured but the response does not say so")
	}

	// And it must not be sitting in the rule row either.
	for _, stored := range store.rules {
		if stored.WebhookSecretRef == secret {
			t.Error("the secret itself was stored as the reference")
		}
		if stored.WebhookSecretRef == "" {
			t.Error("no secret reference was stored, so signing cannot happen")
		}
	}
}

func TestInvalidConditionsAreRejectedWithTheStableCode(t *testing.T) {
	svc, _ := newAlertsService(t, newStubAlerting(), stubPreviewer{})

	cases := map[string]*pb.RuleCondition{
		"no aggregate": {
			Comparator: pb.RuleComparator_RULE_COMPARATOR_GT, Threshold: 1,
			WindowSeconds: 300, CooldownSeconds: 900,
		},
		"cooldown below window": {
			Aggregate:  pb.RuleAggregate_RULE_AGGREGATE_COUNT,
			Comparator: pb.RuleComparator_RULE_COMPARATOR_GT, Threshold: 1,
			WindowSeconds: 600, CooldownSeconds: 60,
		},
		"unknown group field": {
			Aggregate:  pb.RuleAggregate_RULE_AGGREGATE_COUNT,
			Comparator: pb.RuleComparator_RULE_COMPARATOR_GT, Threshold: 1,
			WindowSeconds: 300, CooldownSeconds: 900,
			GroupBy: []string{"correlation_id"},
		},
	}

	for name, condition := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.CreateAlertRule(context.Background(), &pb.CreateAlertRuleRequest{
				Name: "bad rule", Condition: condition,
			})
			if err == nil {
				t.Fatal("an invalid condition was accepted")
			}
			if got := mw.AsError(err).Code; got != mw.CodeRuleConditionInvalid {
				t.Errorf("code = %q, want %q", got, mw.CodeRuleConditionInvalid)
			}
		})
	}
}

// A dry run must report the groups that would NOT fire as well, or an author tuning a
// threshold is working blind.
func TestPreviewReportsBothFiringAndNonFiringGroups(t *testing.T) {
	previewer := stubPreviewer{results: []alerting.Result{
		{GroupValues: map[string]string{"request_host": "a"}, Observed: 50, Fired: true},
		{GroupValues: map[string]string{"request_host": "b"}, Observed: 2, Fired: false},
	}}
	svc, _ := newAlertsService(t, newStubAlerting(), previewer)

	resp, err := svc.PreviewAlertRule(tenantContext(t), &pb.PreviewAlertRuleRequest{
		Condition: validRuleCondition(),
	})
	if err != nil {
		t.Fatalf("PreviewAlertRule: %v", err)
	}

	if len(resp.GetGroups()) != 2 {
		t.Fatalf("%d groups, want both", len(resp.GetGroups()))
	}
	if resp.GetWouldFireCount() != 1 {
		t.Errorf("would_fire_count = %d, want 1", resp.GetWouldFireCount())
	}
}

// A preview must not create anything: it exists so a rule can be judged before it is
// trusted, and a dry run with side effects is not a dry run.
func TestPreviewFiresNothing(t *testing.T) {
	store := newStubAlerting()
	previewer := stubPreviewer{results: []alerting.Result{{Observed: 99, Fired: true}}}
	svc, auditLog := newAlertsService(t, store, previewer)

	if _, err := svc.PreviewAlertRule(tenantContext(t), &pb.PreviewAlertRuleRequest{
		Condition: validRuleCondition(),
	}); err != nil {
		t.Fatalf("PreviewAlertRule: %v", err)
	}

	if len(store.alerts) != 0 {
		t.Errorf("%d alerts were created by a dry run", len(store.alerts))
	}
	if len(store.rules) != 0 {
		t.Errorf("%d rules were created by a dry run", len(store.rules))
	}
	if len(auditLog.records) != 0 {
		t.Errorf("a dry run wrote %d audit entries", len(auditLog.records))
	}
}

// A rule is a control. Changing one must be reviewable without diffing two entries.
func TestRuleChangesAreAuditedWithBeforeAndAfter(t *testing.T) {
	store := newStubAlerting()
	svc, auditLog := newAlertsService(t, store, stubPreviewer{})

	created, err := svc.CreateAlertRule(context.Background(), &pb.CreateAlertRuleRequest{
		Name: "original", Severity: pb.Severity_SEVERITY_LOW,
		Condition: validRuleCondition(), Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}

	renamed := "renamed"
	if _, err := svc.UpdateAlertRule(context.Background(), &pb.UpdateAlertRuleRequest{
		RuleId: created.GetRuleId(), Name: &renamed,
	}); err != nil {
		t.Fatalf("UpdateAlertRule: %v", err)
	}

	if len(auditLog.records) != 2 {
		t.Fatalf("%d audit entries, want create and update", len(auditLog.records))
	}
	update := auditLog.records[1]
	if update.Action != audit.ActionRuleUpdate {
		t.Errorf("action = %q, want %q", update.Action, audit.ActionRuleUpdate)
	}
	if update.BeforeValue == "" || update.AfterValue == "" {
		t.Error("the update was recorded without both a before and an after value")
	}
	if update.BeforeValue == update.AfterValue {
		t.Error("the before and after values are identical, so the change is invisible")
	}
}

// A PATCH that overwrote unset fields with zero values would disable a rule every time
// someone renamed it.
func TestAPartialUpdateLeavesUnsetFieldsAlone(t *testing.T) {
	store := newStubAlerting()
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	created, err := svc.CreateAlertRule(context.Background(), &pb.CreateAlertRuleRequest{
		Name: "original", Severity: pb.Severity_SEVERITY_CRITICAL,
		Condition: validRuleCondition(), Enabled: true,
		WebhookUrl: "https://hooks.example.com/siem",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}

	renamed := "renamed"
	updated, err := svc.UpdateAlertRule(context.Background(), &pb.UpdateAlertRuleRequest{
		RuleId: created.GetRuleId(), Name: &renamed,
	})
	if err != nil {
		t.Fatalf("UpdateAlertRule: %v", err)
	}

	if updated.GetName() != renamed {
		t.Errorf("name = %q, want %q", updated.GetName(), renamed)
	}
	if !updated.GetEnabled() {
		t.Error("renaming a rule disabled it")
	}
	if updated.GetSeverity() != pb.Severity_SEVERITY_CRITICAL {
		t.Errorf("severity = %v, want it unchanged", updated.GetSeverity())
	}
	if updated.GetWebhookUrl() != "https://hooks.example.com/siem" {
		t.Errorf("webhook url = %q, want it unchanged", updated.GetWebhookUrl())
	}
}

// Deleting disables rather than removes: an alert whose rule has vanished cannot be
// explained afterwards.
func TestDeleteDisablesAndKeepsTheRule(t *testing.T) {
	store := newStubAlerting()
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	created, err := svc.CreateAlertRule(context.Background(), &pb.CreateAlertRuleRequest{
		Name: "doomed", Condition: validRuleCondition(), Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}

	if _, err := svc.DeleteAlertRule(context.Background(),
		&pb.DeleteAlertRuleRequest{RuleId: created.GetRuleId()}); err != nil {
		t.Fatalf("DeleteAlertRule: %v", err)
	}

	if len(store.rules) != 1 {
		t.Fatalf("the rule row was removed; an alert referencing it is now unexplainable")
	}
	for _, stored := range store.rules {
		if stored.Enabled {
			t.Error("the rule is still enabled after deletion")
		}
	}
}

// ---------------------------------------------------------------- triage

func seedAlert(store *stubAlerting, state string) chdata.Alert {
	alert := chdata.Alert{
		ID: uuid.New(), RuleID: uuid.New(), FiredAt: alertNow,
		Severity: chdata.SeverityHigh, State: state,
		ObservedValue: 42, Threshold: 10,
		EvidenceCorrelationIDs: []uuid.UUID{uuid.New()},
		NotifyStatus:           chdata.NotifyFailed,
		NotifyAttempts:         5,
		NotifyLastError:        "webhook returned 500",
		Version:                1,
	}
	store.alerts[alert.ID] = alert
	return alert
}

func TestAcknowledgeAndResolveAreAudited(t *testing.T) {
	store := newStubAlerting()
	alert := seedAlert(store, chdata.AlertStateNew)
	svc, auditLog := newAlertsService(t, store, stubPreviewer{})

	acked, err := svc.AcknowledgeAlert(context.Background(),
		&pb.AcknowledgeAlertRequest{AlertId: alert.ID.String(), Note: "looking"})
	if err != nil {
		t.Fatalf("AcknowledgeAlert: %v", err)
	}
	if acked.GetState() != pb.AlertState_ALERT_STATE_ACKNOWLEDGED {
		t.Errorf("state = %v, want acknowledged", acked.GetState())
	}

	resolved, err := svc.ResolveAlert(context.Background(),
		&pb.ResolveAlertRequest{AlertId: alert.ID.String(), Note: "blocked at edge"})
	if err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}
	if resolved.GetState() != pb.AlertState_ALERT_STATE_RESOLVED {
		t.Errorf("state = %v, want resolved", resolved.GetState())
	}

	if len(auditLog.records) != 2 {
		t.Fatalf("%d audit entries, want one per transition", len(auditLog.records))
	}
	for _, record := range auditLog.records {
		if record.Action != audit.ActionAlertStateChange {
			t.Errorf("action = %q, want %q", record.Action, audit.ActionAlertStateChange)
		}
		if record.Detail == "" {
			t.Error("the operator's note was not recorded")
		}
	}
}

// Resolving without acknowledging first stamps both: an operator who fixes the cause
// immediately should not have to click twice, and the trail must still show they saw it.
func TestResolvingWithoutAcknowledgingStampsBoth(t *testing.T) {
	store := newStubAlerting()
	alert := seedAlert(store, chdata.AlertStateNew)
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	resolved, err := svc.ResolveAlert(context.Background(),
		&pb.ResolveAlertRequest{AlertId: alert.ID.String()})
	if err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}

	if resolved.GetAcknowledgedAt() == nil {
		t.Error("the alert was resolved without ever being recorded as seen")
	}
	if resolved.GetResolvedAt() == nil {
		t.Error("no resolution time was recorded")
	}
}

// A delivery failure must be visible where the alert is, not only in a log an analyst
// cannot read (FR-032).
func TestDeliveryFailureIsVisibleOnTheAlert(t *testing.T) {
	store := newStubAlerting()
	alert := seedAlert(store, chdata.AlertStateNew)
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	got, err := svc.GetAlert(context.Background(),
		&pb.GetAlertRequest{AlertId: alert.ID.String()})
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}

	if got.GetNotifyStatus() != pb.NotifyStatus_NOTIFY_STATUS_FAILED {
		t.Errorf("notify_status = %v, want failed", got.GetNotifyStatus())
	}
	if got.GetNotifyLastError() == "" {
		t.Error("the failure reason is not exposed, so the console cannot show it")
	}
	if got.GetNotifyAttempts() == 0 {
		t.Error("the attempt count is not exposed")
	}
}

// The evidence links are what turn an alert into an investigation (SC-006).
func TestAlertsCarryEvidenceLinks(t *testing.T) {
	store := newStubAlerting()
	alert := seedAlert(store, chdata.AlertStateNew)
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	got, err := svc.GetAlert(context.Background(),
		&pb.GetAlertRequest{AlertId: alert.ID.String()})
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if len(got.GetEvidenceCorrelationIds()) != 1 {
		t.Fatalf("%d evidence links, want 1", len(got.GetEvidenceCorrelationIds()))
	}
	if got.GetEvidenceCorrelationIds()[0] != alert.EvidenceCorrelationIDs[0].String() {
		t.Error("the evidence link does not match the correlated record")
	}
}

func TestUnknownAlertIsNotFound(t *testing.T) {
	svc, _ := newAlertsService(t, newStubAlerting(), stubPreviewer{})

	_, err := svc.GetAlert(context.Background(),
		&pb.GetAlertRequest{AlertId: uuid.NewString()})
	if err == nil {
		t.Fatal("an unknown alert returned a record")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 404 {
		t.Errorf("status = %d, want 404", got)
	}
}

func TestMalformedAlertIDIsRejected(t *testing.T) {
	svc, _ := newAlertsService(t, newStubAlerting(), stubPreviewer{})

	_, err := svc.GetAlert(context.Background(), &pb.GetAlertRequest{AlertId: "nope"})
	if err == nil {
		t.Fatal("a malformed alert id was accepted")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
}

func TestAlertEnumsSerializeAsStrings(t *testing.T) {
	store := newStubAlerting()
	alert := seedAlert(store, chdata.AlertStateNew)
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	got, err := svc.GetAlert(context.Background(),
		&pb.GetAlertRequest{AlertId: alert.ID.String()})
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}

	body := encode(t, got)
	for _, field := range []string{"severity", "state", "notifyStatus"} {
		if _, isString := body[field].(string); !isString {
			t.Errorf("%s = %v (%T), want a string", field, body[field], body[field])
		}
	}
}

func TestListAlertsAcceptsATimeRange(t *testing.T) {
	store := newStubAlerting()
	seedAlert(store, chdata.AlertStateNew)
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	resp, err := svc.ListAlerts(context.Background(), &pb.ListAlertsRequest{
		TimeRange: &pb.TimeRange{
			From: timestamppb.New(alertNow.Add(-time.Hour)),
			To:   timestamppb.New(alertNow.Add(time.Hour)),
		},
		State: pb.AlertState_ALERT_STATE_NEW,
	})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(resp.GetAlerts()) != 1 {
		t.Errorf("%d alerts, want 1", len(resp.GetAlerts()))
	}
}

func TestStorageFailuresBecomeInternalErrors(t *testing.T) {
	store := newStubAlerting()
	store.err = errors.New("clickhouse unavailable")
	svc, _ := newAlertsService(t, store, stubPreviewer{})

	_, err := svc.ListAlertRules(context.Background(), &pb.ListAlertRulesRequest{})
	if err == nil {
		t.Fatal("a storage failure was reported as success")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 500 {
		t.Errorf("status = %d, want 500", got)
	}
}
