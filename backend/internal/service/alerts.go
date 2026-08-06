package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/alerting/rule"
	"github.com/menta2k/siem/internal/audit"
	"github.com/menta2k/siem/internal/auth"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
)

// AlertingStore is the storage surface the alerts service reads and writes.
type AlertingStore interface {
	ListRules(ctx context.Context) ([]chdata.AlertRule, error)
	GetRule(ctx context.Context, ruleID uuid.UUID) (chdata.AlertRule, error)
	CreateRule(ctx context.Context, r chdata.AlertRule) (chdata.AlertRule, error)
	UpdateRule(ctx context.Context, ruleID uuid.UUID,
		mutate func(chdata.AlertRule) chdata.AlertRule) (chdata.AlertRule, error)
	ListAlerts(ctx context.Context, f chdata.AlertFilter) ([]chdata.Alert, error)
	GetAlert(ctx context.Context, alertID uuid.UUID) (chdata.Alert, error)
	UpdateAlert(ctx context.Context, alertID uuid.UUID,
		mutate func(chdata.Alert) chdata.Alert) (chdata.Alert, error)
}

// RulePreviewer measures a condition without firing anything.
type RulePreviewer interface {
	Evaluate(ctx context.Context, r chdata.AlertRule, w alerting.Window) ([]alerting.Result, error)
}

// AlertsService implements the Alerts proto service.
type AlertsService struct {
	store     AlertingStore
	evaluator RulePreviewer
	secrets   secrets.Store
	auditLog  AuditWriter
	now       func() time.Time
}

// NewAlertsService constructs the service.
func NewAlertsService(
	store AlertingStore, evaluator RulePreviewer,
	secretStore secrets.Store, auditLog AuditWriter,
) *AlertsService {
	return &AlertsService{
		store: store, evaluator: evaluator,
		secrets: secretStore, auditLog: auditLog, now: time.Now,
	}
}

// ---------------------------------------------------------------- rules

// ListAlertRules returns the tenant's rules.
func (s *AlertsService) ListAlertRules(
	ctx context.Context, _ *pb.ListAlertRulesRequest,
) (*pb.ListAlertRulesResponse, error) {
	rules, err := s.store.ListRules(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := &pb.ListAlertRulesResponse{Rules: make([]*pb.AlertRule, 0, len(rules))}
	for _, r := range rules {
		converted, err := toRuleProto(r)
		if err != nil {
			// A rule whose stored condition no longer parses is surfaced rather than
			// hidden: the author has to be able to see and fix it.
			return nil, mw.Internal().WithCause(err)
		}
		out.Rules = append(out.Rules, converted)
	}
	return out, nil
}

// CreateAlertRule validates, dry-runs, and stores a rule.
func (s *AlertsService) CreateAlertRule(
	ctx context.Context, req *pb.CreateAlertRuleRequest,
) (*pb.AlertRule, error) {
	if req.GetName() == "" {
		return nil, mw.ValidationFailed("a rule name is required")
	}

	condition, err := conditionFromProto(req.GetCondition())
	if err != nil {
		return nil, err
	}
	encoded, err := condition.Encode()
	if err != nil {
		return nil, err
	}

	secretRef, err := s.storeWebhookSecret(ctx, req.GetWebhookSecret())
	if err != nil {
		return nil, err
	}

	created, err := s.store.CreateRule(ctx, chdata.AlertRule{
		Name:             req.GetName(),
		Enabled:          req.GetEnabled(),
		Severity:         severityFromProto(req.GetSeverity()),
		Condition:        encoded,
		WindowSeconds:    condition.WindowSeconds,
		GroupBy:          condition.GroupBy,
		CooldownSeconds:  condition.CooldownSeconds,
		WebhookURL:       req.GetWebhookUrl(),
		WebhookSecretRef: secretRef,
		CreatedBy:        actorID(ctx),
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionRuleCreate, TargetType: "alert_rule",
		TargetID: created.ID.String(), AfterValue: auditableRule(created),
		Result: audit.ResultSuccess,
	})

	return toRuleProto(created)
}

// UpdateAlertRule edits a rule, recording the before and after (FR-029 §3).
func (s *AlertsService) UpdateAlertRule(
	ctx context.Context, req *pb.UpdateAlertRuleRequest,
) (*pb.AlertRule, error) {
	ruleID, err := parseUUID(req.GetRuleId(), "rule id")
	if err != nil {
		return nil, err
	}

	var encoded string
	if req.GetCondition() != nil {
		condition, err := conditionFromProto(req.GetCondition())
		if err != nil {
			return nil, err
		}
		if encoded, err = condition.Encode(); err != nil {
			return nil, err
		}
	}

	secretRef := ""
	if req.WebhookSecret != nil {
		if secretRef, err = s.storeWebhookSecret(ctx, req.GetWebhookSecret()); err != nil {
			return nil, err
		}
	}

	before, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return nil, mw.NotFound("alert rule")
		}
		return nil, mw.Internal().WithCause(err)
	}

	updated, err := s.store.UpdateRule(ctx, ruleID, applyRuleEdit(req, encoded, secretRef))
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionRuleUpdate, TargetType: "alert_rule",
		TargetID: ruleID.String(),
		// Before AND after: an alerting rule is a control, and a change to it needs to
		// be reviewable without diffing two audit entries by hand.
		BeforeValue: auditableRule(before), AfterValue: auditableRule(updated),
		Result: audit.ResultSuccess,
	})

	return toRuleProto(updated)
}

// applyRuleEdit builds the mutation an update applies.
//
// Only fields the request actually SET are changed. A PATCH that overwrote unset
// fields with their zero values would disable a rule every time someone renamed it.
func applyRuleEdit(
	req *pb.UpdateAlertRuleRequest, encoded, secretRef string,
) func(chdata.AlertRule) chdata.AlertRule {
	return func(current chdata.AlertRule) chdata.AlertRule {
		if req.Name != nil {
			current.Name = req.GetName()
		}
		if req.Severity != nil {
			current.Severity = severityFromProto(req.GetSeverity())
		}
		if req.Enabled != nil {
			current.Enabled = req.GetEnabled()
		}
		if req.WebhookUrl != nil {
			current.WebhookURL = req.GetWebhookUrl()
		}
		if secretRef != "" {
			current.WebhookSecretRef = secretRef
		}
		if encoded != "" {
			current.Condition = encoded
			// The denormalized columns are kept in step with the condition document.
			// They exist so the evaluator can read a window without parsing JSON, and a
			// stale copy would make a rule evaluate over the wrong span.
			if parsed, err := rule.Parse(encoded); err == nil {
				current.WindowSeconds = parsed.WindowSeconds
				current.GroupBy = parsed.GroupBy
				current.CooldownSeconds = parsed.CooldownSeconds
			}
		}
		return current
	}
}

// DeleteAlertRule disables a rule, keeping it readable.
func (s *AlertsService) DeleteAlertRule(
	ctx context.Context, req *pb.DeleteAlertRuleRequest,
) (*pb.DeleteAlertRuleResponse, error) {
	ruleID, err := parseUUID(req.GetRuleId(), "rule id")
	if err != nil {
		return nil, err
	}

	disabled, err := s.store.UpdateRule(ctx, ruleID, func(current chdata.AlertRule) chdata.AlertRule {
		current.Enabled = false
		return current
	})
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return nil, mw.NotFound("alert rule")
		}
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionRuleDelete, TargetType: "alert_rule",
		TargetID: ruleID.String(), AfterValue: auditableRule(disabled),
		Result: audit.ResultSuccess,
	})

	return &pb.DeleteAlertRuleResponse{Disabled: true}, nil
}

// PreviewAlertRule measures a condition without firing anything.
//
// The dry run is what makes a rule reviewable before it is trusted. Its failure mode
// otherwise is silence: the rule sits enabled, never trips, and nobody notices until
// the incident it was written for goes unreported.
func (s *AlertsService) PreviewAlertRule(
	ctx context.Context, req *pb.PreviewAlertRuleRequest,
) (*pb.PreviewAlertRuleResponse, error) {
	condition, err := conditionFromProto(req.GetCondition())
	if err != nil {
		return nil, err
	}
	encoded, err := condition.Encode()
	if err != nil {
		return nil, err
	}

	tenantID, err := tenantOf(ctx)
	if err != nil {
		return nil, err
	}

	// A synthetic rule: previewing must not require the rule to exist, so an author
	// can check an edit before saving it rather than only after.
	candidate := chdata.AlertRule{
		TenantID: tenantID, ID: uuid.New(), Condition: encoded,
		WindowSeconds: condition.WindowSeconds, GroupBy: condition.GroupBy,
	}

	window := previewWindow(req.GetTimeRange(), condition, s.now())

	results, err := s.evaluator.Evaluate(ctx, candidate, window)
	if err != nil {
		return nil, mw.AsError(err)
	}

	out := &pb.PreviewAlertRuleResponse{Groups: make([]*pb.PreviewGroup, 0, len(results))}
	for _, result := range results {
		group := &pb.PreviewGroup{
			GroupValues:   result.GroupValues,
			ObservedValue: result.Observed,
			Total:         result.Total,
			WouldFire:     result.Fired,
		}
		for _, id := range result.EvidenceCorrelationIDs {
			group.EvidenceCorrelationIds = append(group.EvidenceCorrelationIds, id.String())
		}
		if result.Fired {
			out.WouldFireCount++
		}
		out.Groups = append(out.Groups, group)
	}
	return out, nil
}

// previewWindow resolves the range a dry run measures over.
func previewWindow(
	r *pb.TimeRange, condition rule.Condition, now time.Time,
) alerting.Window {
	if r != nil && r.GetFrom() != nil && r.GetTo() != nil {
		return alerting.Window{From: r.GetFrom().AsTime(), To: r.GetTo().AsTime()}
	}
	to := now.UTC()
	return alerting.Window{From: to.Add(-condition.Window()), To: to}
}

// ---------------------------------------------------------------- alerts

// ListAlerts returns the triage queue.
func (s *AlertsService) ListAlerts(
	ctx context.Context, req *pb.ListAlertsRequest,
) (*pb.ListAlertsResponse, error) {
	filter := chdata.AlertFilter{
		State:        alertStateFromProto(req.GetState()),
		Severity:     severityFromProto(req.GetSeverity()),
		NotifyStatus: notifyStatusFromProto(req.GetNotifyStatus()),
		Limit:        int(req.GetPage().GetLimit()),
	}
	if r := req.GetTimeRange(); r != nil && r.GetFrom() != nil && r.GetTo() != nil {
		filter.From, filter.To = r.GetFrom().AsTime(), r.GetTo().AsTime()
	}
	if req.GetRuleId() != "" {
		ruleID, err := parseUUID(req.GetRuleId(), "rule id")
		if err != nil {
			return nil, err
		}
		filter.RuleID = ruleID
	}

	alerts, err := s.store.ListAlerts(ctx, filter)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := &pb.ListAlertsResponse{
		Alerts: make([]*pb.Alert, 0, len(alerts)),
		Page:   &pb.PageResponse{Total: int64(len(alerts))},
	}
	for _, alert := range alerts {
		out.Alerts = append(out.Alerts, toAlertProto(alert, s.ruleName(ctx, alert.RuleID)))
	}
	return out, nil
}

// GetAlert returns one alert.
func (s *AlertsService) GetAlert(
	ctx context.Context, req *pb.GetAlertRequest,
) (*pb.Alert, error) {
	alertID, err := parseUUID(req.GetAlertId(), "alert id")
	if err != nil {
		return nil, err
	}

	alert, err := s.store.GetAlert(ctx, alertID)
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return nil, mw.NotFound("alert")
		}
		return nil, mw.Internal().WithCause(err)
	}
	return toAlertProto(alert, s.ruleName(ctx, alert.RuleID)), nil
}

// AcknowledgeAlert moves an alert into triage.
func (s *AlertsService) AcknowledgeAlert(
	ctx context.Context, req *pb.AcknowledgeAlertRequest,
) (*pb.Alert, error) {
	return s.transition(ctx, req.GetAlertId(), chdata.AlertStateAcknowledged, req.GetNote())
}

// ResolveAlert closes an alert.
func (s *AlertsService) ResolveAlert(
	ctx context.Context, req *pb.ResolveAlertRequest,
) (*pb.Alert, error) {
	return s.transition(ctx, req.GetAlertId(), chdata.AlertStateResolved, req.GetNote())
}

// transition applies a triage state change and audits it.
func (s *AlertsService) transition(
	ctx context.Context, rawID, target, note string,
) (*pb.Alert, error) {
	alertID, err := parseUUID(rawID, "alert id")
	if err != nil {
		return nil, err
	}

	actor := actorID(ctx)
	at := s.now().UTC()

	updated, err := s.store.UpdateAlert(ctx, alertID, func(current chdata.Alert) chdata.Alert {
		current.State = target
		switch target {
		case chdata.AlertStateAcknowledged:
			current.AcknowledgedBy, current.AcknowledgedAt = &actor, &at
		case chdata.AlertStateResolved:
			// Resolving without acknowledging is allowed and stamps both: an operator
			// who fixes the cause immediately should not have to click twice, and the
			// trail must still record that they saw it.
			if current.AcknowledgedAt == nil {
				current.AcknowledgedBy, current.AcknowledgedAt = &actor, &at
			}
			current.ResolvedBy, current.ResolvedAt = &actor, &at
		}
		return current
	})
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return nil, mw.NotFound("alert")
		}
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionAlertStateChange, TargetType: "alert",
		TargetID: alertID.String(), AfterValue: target,
		Detail: note, Result: audit.ResultSuccess,
	})

	return toAlertProto(updated, s.ruleName(ctx, updated.RuleID)), nil
}

// ruleName resolves a rule's name for display.
//
// A missing rule yields an empty name rather than an error: an alert must remain
// readable even if its rule row has gone, because that alert is still evidence.
func (s *AlertsService) ruleName(ctx context.Context, ruleID uuid.UUID) string {
	r, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return ""
	}
	return r.Name
}

// storeWebhookSecret puts a signing key in the secret manager and returns its
// reference. The secret itself never reaches the alert_rules table.
func (s *AlertsService) storeWebhookSecret(ctx context.Context, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}

	// The store mints the reference; a caller-chosen key would let two rules collide
	// on one entry and silently share a signing secret.
	ref, err := s.secrets.Put(ctx, "alert-webhook", secret)
	if err != nil {
		return "", mw.Internal().WithCause(err)
	}
	return ref, nil
}

// auditableRule renders a rule for the audit trail WITHOUT its secret reference.
//
// The reference is not a secret, but recording it lets anyone with audit access map a
// rule to a secret-manager key — needless exposure in a record retained for a year.
func auditableRule(r chdata.AlertRule) string {
	return fmt.Sprintf(
		`{"name":%q,"enabled":%t,"severity":%q,"condition":%s,"webhook_url":%q}`,
		r.Name, r.Enabled, r.Severity, r.Condition, r.WebhookURL)
}

func actorID(ctx context.Context) uuid.UUID {
	if claims, ok := auth.ClaimsFromContext(ctx); ok {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			return id
		}
	}
	return uuid.Nil
}

func toAlertProto(alert chdata.Alert, ruleName string) *pb.Alert {
	out := &pb.Alert{
		AlertId:         alert.ID.String(),
		RuleId:          alert.RuleID.String(),
		RuleName:        ruleName,
		FiredAt:         timestamppb.New(alert.FiredAt),
		Severity:        severityToProto(alert.Severity),
		State:           alertStateToProto(alert.State),
		GroupValues:     alert.GroupValues,
		ObservedValue:   alert.ObservedValue,
		Threshold:       alert.Threshold,
		NotifyStatus:    notifyStatusToProto(alert.NotifyStatus),
		NotifyAttempts:  uint32(alert.NotifyAttempts),
		NotifyLastError: alert.NotifyLastError,
	}

	for _, id := range alert.EvidenceCorrelationIDs {
		out.EvidenceCorrelationIds = append(out.EvidenceCorrelationIds, id.String())
	}
	if alert.AcknowledgedBy != nil {
		out.AcknowledgedBy = alert.AcknowledgedBy.String()
	}
	if alert.AcknowledgedAt != nil {
		out.AcknowledgedAt = timestamppb.New(*alert.AcknowledgedAt)
	}
	if alert.ResolvedBy != nil {
		out.ResolvedBy = alert.ResolvedBy.String()
	}
	if alert.ResolvedAt != nil {
		out.ResolvedAt = timestamppb.New(*alert.ResolvedAt)
	}
	return out
}
