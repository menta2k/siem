package service

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/alerting/rule"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
)

// conditionFromProto converts and VALIDATES a rule condition.
//
// Validation happens here rather than at the storage boundary so a malformed rule is
// rejected with a field-level message the author can act on, instead of surfacing as
// an internal error when the evaluator later fails to parse its own row.
func conditionFromProto(c *pb.RuleCondition) (rule.Condition, error) {
	if c == nil {
		return rule.Condition{}, mw.RuleConditionInvalid("a condition is required")
	}

	condition := rule.Condition{
		Filters:           c.GetFilters(),
		OnlyDisagreements: c.GetOnlyDisagreements(),
		MinVendorCount:    c.GetMinVendorCount(),
		Aggregate:         aggregateFromProto(c.GetAggregate()),
		Comparator:        comparatorFromProto(c.GetComparator()),
		Threshold:         c.GetThreshold(),
		WindowSeconds:     c.GetWindowSeconds(),
		GroupBy:           c.GetGroupBy(),
		CooldownSeconds:   c.GetCooldownSeconds(),
	}

	if err := condition.Validate(); err != nil {
		return rule.Condition{}, err
	}
	return condition, nil
}

func conditionToProto(c rule.Condition) *pb.RuleCondition {
	return &pb.RuleCondition{
		Filters:           c.Filters,
		OnlyDisagreements: c.OnlyDisagreements,
		MinVendorCount:    c.MinVendorCount,
		Aggregate:         aggregateToProto(c.Aggregate),
		Comparator:        comparatorToProto(c.Comparator),
		Threshold:         c.Threshold,
		WindowSeconds:     c.WindowSeconds,
		GroupBy:           c.GroupBy,
		CooldownSeconds:   c.CooldownSeconds,
	}
}

func toRuleProto(r chdata.AlertRule) (*pb.AlertRule, error) {
	condition, err := rule.Parse(r.Condition)
	if err != nil {
		return nil, err
	}

	return &pb.AlertRule{
		RuleId:    r.ID.String(),
		Name:      r.Name,
		Enabled:   r.Enabled,
		Severity:  severityToProto(r.Severity),
		Condition: conditionToProto(condition),

		WebhookUrl: r.WebhookURL,
		// The secret is never returned; only whether one is configured, which is what
		// the console needs to render "signing enabled" without exposing the key.
		WebhookSigningConfigured: r.WebhookSecretRef != "",

		CreatedBy: r.CreatedBy.String(),
		CreatedAt: timestamppb.New(r.CreatedAt),
		UpdatedAt: timestamppb.New(r.UpdatedAt),
	}, nil
}

func aggregateFromProto(a pb.RuleAggregate) rule.Aggregate {
	switch a {
	case pb.RuleAggregate_RULE_AGGREGATE_COUNT:
		return rule.AggregateCount
	case pb.RuleAggregate_RULE_AGGREGATE_RATE:
		return rule.AggregateRate
	case pb.RuleAggregate_RULE_AGGREGATE_DISTINCT_IPS:
		return rule.AggregateDistinctIPs
	case pb.RuleAggregate_RULE_AGGREGATE_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func aggregateToProto(a rule.Aggregate) pb.RuleAggregate {
	switch a {
	case rule.AggregateCount:
		return pb.RuleAggregate_RULE_AGGREGATE_COUNT
	case rule.AggregateRate:
		return pb.RuleAggregate_RULE_AGGREGATE_RATE
	case rule.AggregateDistinctIPs:
		return pb.RuleAggregate_RULE_AGGREGATE_DISTINCT_IPS
	default:
		return pb.RuleAggregate_RULE_AGGREGATE_UNSPECIFIED
	}
}

func comparatorFromProto(c pb.RuleComparator) rule.Comparator {
	switch c {
	case pb.RuleComparator_RULE_COMPARATOR_GT:
		return rule.ComparatorGreaterThan
	case pb.RuleComparator_RULE_COMPARATOR_GTE:
		return rule.ComparatorGreaterEqual
	case pb.RuleComparator_RULE_COMPARATOR_LT:
		return rule.ComparatorLessThan
	case pb.RuleComparator_RULE_COMPARATOR_LTE:
		return rule.ComparatorLessEqual
	case pb.RuleComparator_RULE_COMPARATOR_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func comparatorToProto(c rule.Comparator) pb.RuleComparator {
	switch c {
	case rule.ComparatorGreaterThan:
		return pb.RuleComparator_RULE_COMPARATOR_GT
	case rule.ComparatorGreaterEqual:
		return pb.RuleComparator_RULE_COMPARATOR_GTE
	case rule.ComparatorLessThan:
		return pb.RuleComparator_RULE_COMPARATOR_LT
	case rule.ComparatorLessEqual:
		return pb.RuleComparator_RULE_COMPARATOR_LTE
	default:
		return pb.RuleComparator_RULE_COMPARATOR_UNSPECIFIED
	}
}

func severityFromProto(s pb.Severity) string {
	switch s {
	case pb.Severity_SEVERITY_LOW:
		return chdata.SeverityLow
	case pb.Severity_SEVERITY_MEDIUM:
		return chdata.SeverityMedium
	case pb.Severity_SEVERITY_HIGH:
		return chdata.SeverityHigh
	case pb.Severity_SEVERITY_CRITICAL:
		return chdata.SeverityCritical
	case pb.Severity_SEVERITY_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func severityToProto(s string) pb.Severity {
	switch s {
	case chdata.SeverityLow:
		return pb.Severity_SEVERITY_LOW
	case chdata.SeverityMedium:
		return pb.Severity_SEVERITY_MEDIUM
	case chdata.SeverityHigh:
		return pb.Severity_SEVERITY_HIGH
	case chdata.SeverityCritical:
		return pb.Severity_SEVERITY_CRITICAL
	default:
		return pb.Severity_SEVERITY_UNSPECIFIED
	}
}

func alertStateFromProto(s pb.AlertState) string {
	switch s {
	case pb.AlertState_ALERT_STATE_NEW:
		return chdata.AlertStateNew
	case pb.AlertState_ALERT_STATE_ACKNOWLEDGED:
		return chdata.AlertStateAcknowledged
	case pb.AlertState_ALERT_STATE_RESOLVED:
		return chdata.AlertStateResolved
	case pb.AlertState_ALERT_STATE_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func alertStateToProto(s string) pb.AlertState {
	switch s {
	case chdata.AlertStateNew:
		return pb.AlertState_ALERT_STATE_NEW
	case chdata.AlertStateAcknowledged:
		return pb.AlertState_ALERT_STATE_ACKNOWLEDGED
	case chdata.AlertStateResolved:
		return pb.AlertState_ALERT_STATE_RESOLVED
	default:
		return pb.AlertState_ALERT_STATE_UNSPECIFIED
	}
}

func notifyStatusFromProto(s pb.NotifyStatus) string {
	switch s {
	case pb.NotifyStatus_NOTIFY_STATUS_PENDING:
		return chdata.NotifyPending
	case pb.NotifyStatus_NOTIFY_STATUS_DELIVERED:
		return chdata.NotifyDelivered
	case pb.NotifyStatus_NOTIFY_STATUS_FAILED:
		return chdata.NotifyFailed
	case pb.NotifyStatus_NOTIFY_STATUS_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func notifyStatusToProto(s string) pb.NotifyStatus {
	switch s {
	case chdata.NotifyPending:
		return pb.NotifyStatus_NOTIFY_STATUS_PENDING
	case chdata.NotifyDelivered:
		return pb.NotifyStatus_NOTIFY_STATUS_DELIVERED
	case chdata.NotifyFailed:
		return pb.NotifyStatus_NOTIFY_STATUS_FAILED
	default:
		return pb.NotifyStatus_NOTIFY_STATUS_UNSPECIFIED
	}
}

// tenantOf reads the request's tenant, which a preview needs to scope its measurement.
func tenantOf(ctx context.Context) (uuid.UUID, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return uuid.Nil, mw.AsError(err)
	}
	return tenantID, nil
}
