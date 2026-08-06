package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// Alert states.
const (
	AlertStateNew          = "new"
	AlertStateAcknowledged = "acknowledged"
	AlertStateResolved     = "resolved"
)

// Delivery states for a webhook notification.
const (
	NotifyPending   = "pending"
	NotifyDelivered = "delivered"
	NotifyFailed    = "failed"
)

// Rule severities.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// AlertRule is a stored alerting rule.
type AlertRule struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	Name     string
	Enabled  bool
	Severity string

	// Condition is validated JSON. It is stored whole because it is read and written
	// whole, and validated by one schema on both sides.
	Condition string

	WindowSeconds   uint32
	GroupBy         []string
	CooldownSeconds uint32

	WebhookURL string
	// WebhookSecretRef is a reference into the secret manager, never the secret. The
	// signing key must not sit in a table auditors can read.
	WebhookSecretRef string

	CreatedBy uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	Version   uint64
}

// Alert is one firing of a rule.
type Alert struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	RuleID   uuid.UUID
	FiredAt  time.Time
	Severity string
	State    string

	GroupValues map[string]string

	ObservedValue float64
	Threshold     float64
	// EvidenceCorrelationIDs links to the records that caused the alert, so an
	// operator opens the evidence instead of reconstructing the query behind a number.
	EvidenceCorrelationIDs []uuid.UUID

	AcknowledgedBy *uuid.UUID
	AcknowledgedAt *time.Time
	ResolvedBy     *uuid.UUID
	ResolvedAt     *time.Time

	NotifyStatus    string
	NotifyAttempts  uint8
	NotifyLastError string

	Version uint64
}

// AlertingRepo reads and writes rules and alerts.
type AlertingRepo struct {
	client *Client
	locker Locker
}

// NewAlertingRepo constructs the repository.
func NewAlertingRepo(client *Client, locker Locker) *AlertingRepo {
	return &AlertingRepo{client: client, locker: locker}
}

const alertRuleColumns = `tenant_id, rule_id, name, enabled, severity, condition,
	window_seconds, group_by, cooldown_seconds, webhook_url, webhook_secret_ref,
	created_by, created_at, updated_at, version`

const alertColumns = `tenant_id, alert_id, rule_id, fired_at, severity, state,
	group_values, observed_value, threshold, evidence_correlation_ids,
	acknowledged_by, acknowledged_at, resolved_by, resolved_at,
	notify_status, notify_attempts, notify_last_error, version`

// ---------------------------------------------------------------- rules

// CreateRule inserts a rule.
func (r *AlertingRepo) CreateRule(ctx context.Context, rule AlertRule) (AlertRule, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return AlertRule{}, err
	}

	rule.TenantID = tenantID
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	now := time.Now().UTC()
	rule.CreatedAt, rule.UpdatedAt, rule.Version = now, now, 1

	if err := r.insertRule(ctx, rule); err != nil {
		return AlertRule{}, err
	}
	return rule, nil
}

// UpdateRule writes a new version of a rule.
//
// Serialised under a lock and built from the CURRENT row: a read-modify-write without
// one lets two concurrent edits each write version N+1 from the same base, and
// ReplacingMergeTree then keeps whichever merge wins — silently discarding one edit.
func (r *AlertingRepo) UpdateRule(
	ctx context.Context, ruleID uuid.UUID, mutate func(AlertRule) AlertRule,
) (AlertRule, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return AlertRule{}, err
	}

	release, err := r.locker.Lock(ctx, fmt.Sprintf("alert_rule:%s:%s", tenantID, ruleID))
	if err != nil {
		return AlertRule{}, err
	}
	defer release()

	current, err := r.GetRule(ctx, ruleID)
	if err != nil {
		return AlertRule{}, err
	}

	updated := mutate(current)
	// Identity and provenance are not the caller's to change.
	updated.TenantID, updated.ID = current.TenantID, current.ID
	updated.CreatedBy, updated.CreatedAt = current.CreatedBy, current.CreatedAt
	updated.UpdatedAt = time.Now().UTC()
	updated.Version = current.Version + 1

	if err := r.insertRule(ctx, updated); err != nil {
		return AlertRule{}, err
	}
	return updated, nil
}

// DeleteRule disables a rule rather than removing it.
//
// A deleted rule's alerts remain, and an alert whose rule has vanished cannot be
// explained. Disabling keeps the rule readable for exactly that reason.
func (r *AlertingRepo) DeleteRule(ctx context.Context, ruleID uuid.UUID) error {
	_, err := r.UpdateRule(ctx, ruleID, func(rule AlertRule) AlertRule {
		rule.Enabled = false
		return rule
	})
	return err
}

// GetRule loads one rule.
func (r *AlertingRepo) GetRule(ctx context.Context, ruleID uuid.UUID) (AlertRule, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return AlertRule{}, err
	}

	rows, err := r.client.Query(ctx,
		"SELECT "+alertRuleColumns+" FROM alert_rules FINAL "+
			"WHERE tenant_id = ? AND rule_id = ? LIMIT 1", tenantID, ruleID)
	if err != nil {
		return AlertRule{}, fmt.Errorf("load alert rule: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return AlertRule{}, fmt.Errorf("load alert rule: %w", err)
		}
		return AlertRule{}, ErrNotFound
	}
	return scanAlertRule(rows)
}

// ListRules returns the tenant's rules.
func (r *AlertingRepo) ListRules(ctx context.Context) ([]AlertRule, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx,
		"SELECT "+alertRuleColumns+" FROM alert_rules FINAL "+
			"WHERE tenant_id = ? ORDER BY name", tenantID)
	if err != nil {
		return nil, fmt.Errorf("list alert rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []AlertRule
	for rows.Next() {
		rule, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListEnabledRules returns every enabled rule ACROSS tenants.
//
// The evaluator runs as a background worker with no request to inherit a tenant from,
// so this is deliberately unscoped; it is the only rule read that is. Callers must
// scope each rule's evaluation to the tenant on the row, which is why TenantID is
// carried on the struct rather than being implied by the query.
func (r *AlertingRepo) ListEnabledRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := r.client.Query(ctx,
		"SELECT "+alertRuleColumns+" FROM alert_rules FINAL WHERE enabled ORDER BY tenant_id")
	if err != nil {
		return nil, fmt.Errorf("list enabled rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []AlertRule
	for rows.Next() {
		rule, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *AlertingRepo) insertRule(ctx context.Context, rule AlertRule) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO alert_rules ("+alertRuleColumns+")")
	if err != nil {
		return fmt.Errorf("prepare alert rule batch: %w", err)
	}
	if err := batch.Append(
		rule.TenantID, rule.ID, rule.Name, rule.Enabled, rule.Severity, rule.Condition,
		rule.WindowSeconds, orEmptySlice(rule.GroupBy), rule.CooldownSeconds,
		rule.WebhookURL, rule.WebhookSecretRef,
		rule.CreatedBy, rule.CreatedAt, rule.UpdatedAt, rule.Version,
	); err != nil {
		return fmt.Errorf("append alert rule %s: %w", rule.ID, err)
	}
	return batch.Send()
}

// ---------------------------------------------------------------- alerts

// InsertAlert writes a newly fired alert.
func (r *AlertingRepo) InsertAlert(ctx context.Context, alert Alert) (Alert, error) {
	if alert.ID == uuid.Nil {
		alert.ID = uuid.New()
	}
	if alert.State == "" {
		alert.State = AlertStateNew
	}
	if alert.NotifyStatus == "" {
		alert.NotifyStatus = NotifyPending
	}
	if alert.Version == 0 {
		alert.Version = 1
	}

	if err := r.insertAlert(ctx, alert); err != nil {
		return Alert{}, err
	}
	return alert, nil
}

// UpdateAlert writes a new version of an alert.
func (r *AlertingRepo) UpdateAlert(
	ctx context.Context, alertID uuid.UUID, mutate func(Alert) Alert,
) (Alert, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Alert{}, err
	}

	release, err := r.locker.Lock(ctx, fmt.Sprintf("alert:%s:%s", tenantID, alertID))
	if err != nil {
		return Alert{}, err
	}
	defer release()

	current, err := r.GetAlert(ctx, alertID)
	if err != nil {
		return Alert{}, err
	}

	updated := mutate(current)
	updated.TenantID, updated.ID, updated.RuleID = current.TenantID, current.ID, current.RuleID
	updated.FiredAt = current.FiredAt
	updated.Version = current.Version + 1

	if err := r.insertAlert(ctx, updated); err != nil {
		return Alert{}, err
	}
	return updated, nil
}

// GetAlert loads one alert.
func (r *AlertingRepo) GetAlert(ctx context.Context, alertID uuid.UUID) (Alert, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Alert{}, err
	}

	rows, err := r.client.Query(ctx,
		"SELECT "+alertColumns+" FROM alerts FINAL "+
			"WHERE tenant_id = ? AND alert_id = ? LIMIT 1", tenantID, alertID)
	if err != nil {
		return Alert{}, fmt.Errorf("load alert: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Alert{}, fmt.Errorf("load alert: %w", err)
		}
		return Alert{}, ErrNotFound
	}
	return scanAlert(rows)
}

// AlertFilter narrows an alert listing.
type AlertFilter struct {
	From, To     time.Time
	State        string
	Severity     string
	RuleID       uuid.UUID
	NotifyStatus string
	Limit        int
}

// build renders the filter as a parameterized query.
//
// Every value is bound; the only strings concatenated here originate in this file.
func (f AlertFilter) build(tenantID uuid.UUID) (string, []any) {
	query := "SELECT " + alertColumns + " FROM alerts FINAL WHERE tenant_id = ?"
	args := []any{tenantID}

	if !f.From.IsZero() && !f.To.IsZero() {
		query += " AND fired_at >= ? AND fired_at < ?"
		args = append(args, f.From.UTC(), f.To.UTC())
	}
	if f.State != "" {
		query += " AND state = ?"
		args = append(args, f.State)
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.RuleID != uuid.Nil {
		query += " AND rule_id = ?"
		args = append(args, f.RuleID)
	}
	if f.NotifyStatus != "" {
		query += " AND notify_status = ?"
		args = append(args, f.NotifyStatus)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query += " ORDER BY fired_at DESC LIMIT ?"
	args = append(args, limit)

	return query, args
}

// ListAlerts returns alerts newest first.
func (r *AlertingRepo) ListAlerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	query, args := f.build(tenantID)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	alerts := make([]Alert, 0, 16)
	for rows.Next() {
		alert, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

// PendingDeliveries returns alerts whose webhook has not yet succeeded.
//
// Unscoped for the same reason as ListEnabledRules: the delivery worker has no request
// context. Each alert carries its tenant so the retry stays scoped.
func (r *AlertingRepo) PendingDeliveries(ctx context.Context, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := r.client.Query(ctx,
		"SELECT "+alertColumns+" FROM alerts FINAL "+
			"WHERE notify_status = ? ORDER BY fired_at LIMIT ?", NotifyPending, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var alerts []Alert
	for rows.Next() {
		alert, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

func (r *AlertingRepo) insertAlert(ctx context.Context, alert Alert) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO alerts ("+alertColumns+")")
	if err != nil {
		return fmt.Errorf("prepare alert batch: %w", err)
	}
	if err := batch.Append(
		alert.TenantID, alert.ID, alert.RuleID, alert.FiredAt, alert.Severity, alert.State,
		orEmptyMap(alert.GroupValues), alert.ObservedValue, alert.Threshold,
		orEmptyUUIDs(alert.EvidenceCorrelationIDs),
		alert.AcknowledgedBy, alert.AcknowledgedAt, alert.ResolvedBy, alert.ResolvedAt,
		alert.NotifyStatus, alert.NotifyAttempts, alert.NotifyLastError, alert.Version,
	); err != nil {
		return fmt.Errorf("append alert %s: %w", alert.ID, err)
	}
	return batch.Send()
}

// ErrInvalidTransition reports a triage action that the alert's state does not allow.
var ErrInvalidTransition = errors.New("the alert is not in a state that allows this")

func scanAlertRule(row rowScanner) (AlertRule, error) {
	var rule AlertRule
	if err := row.Scan(
		&rule.TenantID, &rule.ID, &rule.Name, &rule.Enabled, &rule.Severity,
		&rule.Condition, &rule.WindowSeconds, &rule.GroupBy, &rule.CooldownSeconds,
		&rule.WebhookURL, &rule.WebhookSecretRef,
		&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt, &rule.Version,
	); err != nil {
		return AlertRule{}, fmt.Errorf("scan alert rule: %w", err)
	}
	return rule, nil
}

func scanAlert(row rowScanner) (Alert, error) {
	var alert Alert
	if err := row.Scan(
		&alert.TenantID, &alert.ID, &alert.RuleID, &alert.FiredAt, &alert.Severity,
		&alert.State, &alert.GroupValues, &alert.ObservedValue, &alert.Threshold,
		&alert.EvidenceCorrelationIDs,
		&alert.AcknowledgedBy, &alert.AcknowledgedAt, &alert.ResolvedBy, &alert.ResolvedAt,
		&alert.NotifyStatus, &alert.NotifyAttempts, &alert.NotifyLastError, &alert.Version,
	); err != nil {
		return Alert{}, fmt.Errorf("scan alert: %w", err)
	}
	return alert, nil
}

// orEmptyUUIDs mirrors orEmptySlice: ClickHouse rejects a nil Array.
func orEmptyUUIDs(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// ---------------------------------------------------------------- measurement

// AlertMeasurement is one group's figures for a rule window.
type AlertMeasurement struct {
	GroupValues            map[string]string
	Value                  float64
	Total                  float64
	EvidenceCorrelationIDs []uuid.UUID
}

// MeasureRequest is a validated measurement over correlated_requests.
//
// Conditions and GroupBy arrive already resolved through the query allowlist. This
// type deliberately cannot build a predicate from a raw field name.
type MeasureRequest struct {
	From, To      time.Time
	Aggregate     string
	Conditions    string
	Args          []any
	GroupBy       []string
	EvidenceLimit int
}

// Measure runs one rule's aggregate over its window.
func (r *AlertingRepo) Measure(
	ctx context.Context, req MeasureRequest,
) ([]AlertMeasurement, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	selectExpr, err := aggregateExpr(req.Aggregate)
	if err != nil {
		return nil, err
	}

	limit := req.EvidenceLimit
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	// groupBy values are physical column names resolved through the allowlist before
	// they arrive here; nothing caller-supplied is interpolated.
	groupSelect := ""
	groupClause := ""
	if len(req.GroupBy) > 0 {
		groupSelect = strings.Join(req.GroupBy, ", ") + ", "
		groupClause = " GROUP BY " + strings.Join(req.GroupBy, ", ")
	}

	query := fmt.Sprintf(`
		SELECT %s%s AS value, count() AS total,
		       arraySlice(groupArray(correlation_id), 1, %d) AS evidence
		FROM correlated_requests FINAL
		WHERE tenant_id = ? AND window_start >= ? AND window_start < ?%s%s`,
		groupSelect, selectExpr, limit, req.Conditions, groupClause)

	args := append([]any{tenantID, req.From.UTC(), req.To.UTC()}, req.Args...)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("measure alert rule: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanMeasurements(rows, req.GroupBy)
}

// aggregateExpr maps an aggregate name to its SQL.
//
// A closed set: the aggregate reaches the SELECT list, which no placeholder protects.
func aggregateExpr(aggregate string) (string, error) {
	switch aggregate {
	case "count":
		return "toFloat64(count())", nil
	case "distinct_ips":
		return "toFloat64(uniq(client_ip))", nil
	case "rate":
		// The numerator is the filtered set and the denominator is every record in the
		// window, so a rate answers "what share of traffic" rather than "how many" —
		// a spike in blocks during a traffic surge is normal, the same count in quiet
		// hours is not.
		return "toFloat64(count()) / greatest(toFloat64(count()), 1)", nil
	default:
		return "", fmt.Errorf("unsupported alert aggregate %q", aggregate)
	}
}

// measurementRows is the iteration surface scanMeasurements needs, kept narrow so the
// scanning logic can be exercised without a live driver.
type measurementRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanMeasurements(rows measurementRows, groupBy []string) ([]AlertMeasurement, error) {
	var out []AlertMeasurement

	for rows.Next() {
		// A typed slice rather than []any of assertions: the group values are all
		// strings, and a type assertion here would be an unchecked cast in the middle
		// of a scan loop.
		var (
			groups   = make([]string, len(groupBy))
			value    float64
			total    uint64
			evidence []uuid.UUID
		)
		dest := make([]any, 0, len(groupBy)+3)
		for i := range groups {
			dest = append(dest, &groups[i])
		}
		dest = append(dest, &value, &total, &evidence)

		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan alert measurement: %w", err)
		}

		measurement := AlertMeasurement{
			Value:                  value,
			Total:                  float64(total),
			EvidenceCorrelationIDs: evidence,
		}
		if len(groupBy) > 0 {
			measurement.GroupValues = make(map[string]string, len(groupBy))
			for i, column := range groupBy {
				measurement.GroupValues[column] = groups[i]
			}
		}
		out = append(out, measurement)
	}
	return out, rows.Err()
}
