package service

import (
	"context"
	"sort"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
)

// WAFMigrationReader is the storage surface the migration stages read through.
type WAFMigrationReader interface {
	Uncovered(
		ctx context.Context, q chdata.DashboardQuery, filter chdata.WAFMigrationFilter,
	) ([]chdata.WAFUncoveredGroup, error)
	RuleAgreement(
		ctx context.Context, q chdata.DashboardQuery, filter chdata.WAFMigrationFilter,
		readings, monitoredRuleIDs []string,
	) ([]chdata.WAFRuleAgreement, error)
	Samples(
		ctx context.Context, sel chdata.WAFMigrationSelector, q chdata.DashboardQuery,
	) ([]chdata.WAFMigrationSample, error)
}

// MonitoredRuleSource lists the Cloudflare rules configured not to enforce.
//
// A separate surface from RuleNamer because it answers a different question: not "what is
// this rule called" but "which rules are still waiting to be trusted". The rule's own
// configuration is the only place that answer lives — the action recorded against a
// request is whichever rule decided it, which for a log-mode rule is somebody else.
type MonitoredRuleSource interface {
	MonitoredRules(ctx context.Context) (map[string]string, error)
}

// WAFMigrationService implements the WafMigration proto service.
//
// Three stages of one move: find what Cloudflare cannot see, confirm what it sees
// agrees with F5, and separate out where it does not. Like the tuning service it
// reports evidence and never generates configuration — it says a rule is ready to
// enforce and why, and writing it belongs to whoever owns the consequences.
type WAFMigrationService struct {
	waf    WAFMigrationReader
	limits query.Limits
	// rules names a rule id, through the same resolver the rest of the console uses.
	// Optional: a deployment with no Cloudflare token gets bare ids.
	rules RuleNamer
	// monitored decides which rules are migration candidates at all.
	monitored MonitoredRuleSource
	now       func() time.Time
}

// NewWAFMigrationService constructs the service.
func NewWAFMigrationService(
	waf WAFMigrationReader, limits query.Limits, rules RuleNamer,
	monitored MonitoredRuleSource,
) *WAFMigrationService {
	return &WAFMigrationService{
		waf: waf, limits: limits, rules: rules, monitored: monitored, now: time.Now,
	}
}

// migrationQuery validates the range and limit the way every panel does.
func (s *WAFMigrationService) migrationQuery(
	timeRange *pb.TimeRange, limit uint32,
) (chdata.DashboardQuery, error) {
	if timeRange == nil {
		return chdata.DashboardQuery{}, mw.TimeRangeRequired()
	}
	rng, err := s.limits.Range(
		timeRange.GetFrom().AsTime(), timeRange.GetTo().AsTime(), s.now())
	if err != nil {
		return chdata.DashboardQuery{}, err
	}
	return chdata.DashboardQuery{Range: rng, Limit: int(limit)}, nil
}

// GetUncovered returns traffic F5 blocked that no Cloudflare rule matched.
func (s *WAFMigrationService) GetUncovered(
	ctx context.Context, req *pb.WafMigrationRequest,
) (*pb.WafUncoveredPanel, error) {
	q, err := s.migrationQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	groups, err := s.waf.Uncovered(ctx, q, chdata.WAFMigrationFilter{
		RequestHost: req.GetRequestHost(),
	})
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.WafUncoveredPanel{Groups: make([]*pb.WafUncoveredGroup, 0, len(groups))}
	for _, g := range groups {
		out.Groups = append(out.Groups, &pb.WafUncoveredGroup{
			Violation:             g.Violation,
			RequestHost:           g.RequestHost,
			RequestMethod:         g.RequestMethod,
			Requests:              g.Requests,
			Paths:                 g.Paths,
			Clients:               g.Clients,
			CloudflareAllowlisted: g.CloudflareAllowlisted,
			FirstSeen:             timestamppb.New(g.FirstSeen),
			LastSeen:              timestamppb.New(g.LastSeen),
		})
	}
	return out, nil
}

// GetReadyToEnforce returns logging Cloudflare rules that F5 independently blocks.
//
// `disputed` is included alongside `ready`. A rule the two vendors mostly agree on is
// the point of the stage, but one they half agree on is the case that most needs a
// person to look at it, and leaving it off both this stage and the false-positive stage
// would make it invisible on the only screen built to find it.
func (s *WAFMigrationService) GetReadyToEnforce(
	ctx context.Context, req *pb.WafMigrationRequest,
) (*pb.WafRuleAgreementPanel, error) {
	return s.agreement(ctx, req, []string{chdata.ReadingReady, chdata.ReadingDisputed})
}

// GetFalsePositives returns logging Cloudflare rules on traffic F5 lets through.
func (s *WAFMigrationService) GetFalsePositives(
	ctx context.Context, req *pb.WafMigrationRequest,
) (*pb.WafRuleAgreementPanel, error) {
	return s.agreement(ctx, req, []string{chdata.ReadingFalsePositive})
}

// agreement serves both rule stages: they are the same measurement read from opposite
// ends, and one query means the two can never disagree about the same rule.
func (s *WAFMigrationService) agreement(
	ctx context.Context, req *pb.WafMigrationRequest, readings []string,
) (*pb.WafRuleAgreementPanel, error) {
	q, err := s.migrationQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	// The candidates, and each one's configured action, before anything is counted. A
	// deployment with no Cloudflare token cannot know which rules are in log mode, and
	// answering with every rule that ever matched would fill the worklist with work
	// already finished.
	actions, err := s.monitoredActions(ctx)
	if err != nil {
		return nil, err
	}
	if len(actions) == 0 {
		return &pb.WafRuleAgreementPanel{}, nil
	}

	candidates := make([]string, 0, len(actions))
	for ruleID := range actions {
		candidates = append(candidates, ruleID)
	}
	// Sorted so the same request produces the same query, which keeps a slow one
	// reproducible and lets ClickHouse reuse its cache.
	sort.Strings(candidates)

	rules, err := s.waf.RuleAgreement(ctx, q, chdata.WAFMigrationFilter{
		RequestHost: req.GetRequestHost(),
	}, readings, candidates)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.WafRuleAgreementPanel{Rules: make([]*pb.WafRuleAgreement, 0, len(rules))}
	for _, r := range rules {
		out.Rules = append(out.Rules, &pb.WafRuleAgreement{
			RuleId:      r.RuleID,
			Action:      actions[r.RuleID],
			Correlated:  r.Correlated,
			F5Blocked:   r.F5Blocked,
			F5Flagged:   r.F5Flagged,
			F5Allowed:   r.F5Allowed,
			Hosts:       r.Hosts,
			RequestHost: r.RequestHost,
			Reading:     r.Reading,
			FirstSeen:   timestamppb.New(r.FirstSeen),
			LastSeen:    timestamppb.New(r.LastSeen),
		})
	}
	describeAgreementRules(ctx, s.rules, out.Rules)
	return out, nil
}

// monitoredActions reads the candidate rules, tolerating a deployment that has none.
func (s *WAFMigrationService) monitoredActions(
	ctx context.Context,
) (map[string]string, error) {
	if s.monitored == nil {
		return nil, nil
	}
	actions, err := s.monitored.MonitoredRules(ctx)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	return actions, nil
}

// GetMigrationSamples returns the requests behind one row, with both verdicts on each.
func (s *WAFMigrationService) GetMigrationSamples(
	ctx context.Context, req *pb.WafMigrationSampleRequest,
) (*pb.WafMigrationSamplePanel, error) {
	// One or the other keys the group. Without either this is "every correlated request
	// in the range", which is a search, and the search page already does that better.
	if req.GetViolation() == "" && req.GetRuleId() == "" {
		return nil, mw.ValidationFailed("a violation or a rule id is required")
	}
	if v := req.GetF5Verdict(); v != "" && !migrationVerdicts[v] {
		return nil, mw.ValidationFailed(
			"the F5 verdict must be one of: blocked, monitored, allowed")
	}
	if v := req.GetCloudflareVerdict(); v != "" && !migrationVerdicts[v] {
		return nil, mw.ValidationFailed(
			"the Cloudflare verdict must be one of: blocked, monitored, allowed")
	}

	q, err := s.migrationQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	samples, err := s.waf.Samples(ctx, chdata.WAFMigrationSelector{
		Violation:         req.GetViolation(),
		RuleID:            req.GetRuleId(),
		RequestHost:       req.GetRequestHost(),
		RequestMethod:     req.GetRequestMethod(),
		F5Verdict:         req.GetF5Verdict(),
		CloudflareVerdict: req.GetCloudflareVerdict(),
	}, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	return migrationSamplePanel(samples), nil
}

// migrationSamplePanel renders the stored samples onto the wire.
func migrationSamplePanel(samples []chdata.WAFMigrationSample) *pb.WafMigrationSamplePanel {
	out := &pb.WafMigrationSamplePanel{
		Samples: make([]*pb.WafMigrationSample, 0, len(samples)),
	}
	for _, sample := range samples {
		item := &pb.WafMigrationSample{
			CorrelationId:     sample.CorrelationID,
			F5EventId:         sample.F5EventID,
			CloudflareEventId: sample.CloudflareEventID,
			EventTime:         timestamppb.New(sample.EventTime),
			Country:           sample.Country,
			ClientAsn:         sample.ClientASN,
			RequestHost:       sample.RequestHost,
			RequestPath:       sample.RequestPath,
			RequestQuery:      sample.RequestQuery,
			RequestMethod:     sample.RequestMethod,
			UserAgent:         sample.UserAgent,
			F5Verdict:         sample.F5Verdict,
			F5Violations:      sample.F5Violations,
			CloudflareVerdict: sample.CloudflareVerdict,
			CloudflareRuleId:  sample.CloudflareRuleID,
			AttackScore:       uint32(sample.AttackScore),
		}
		// Absent rather than "::" for an event carrying no client address: a rendered
		// zero address reads as a real one.
		if sample.ClientIP != nil {
			item.ClientIp = sample.ClientIP.String()
		}
		out.Samples = append(out.Samples, item)
	}
	return out
}

// migrationVerdicts is what an F5 verdict filter may say. Validated rather than passed
// through: an unrecognised value would silently return nothing, which reads as "no such
// traffic" rather than "that is not a verdict".
var migrationVerdicts = map[string]bool{
	vendors.VerdictBlocked:   true,
	vendors.VerdictMonitored: true,
	vendors.VerdictAllowed:   true,
}

// describeAgreementRules fills in rule names for a page, in ONE lookup. Resolving per
// row would turn one query into fifty.
func describeAgreementRules(
	ctx context.Context, namer RuleNamer, rules []*pb.WafRuleAgreement,
) {
	if namer == nil || len(rules) == 0 {
		return
	}

	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		if r.GetRuleId() != "" {
			ids = append(ids, r.GetRuleId())
		}
	}

	names := namer.Describe(ctx, ids)
	for _, r := range rules {
		if name := names[r.GetRuleId()]; name != "" {
			r.RuleDescription = name
		}
	}
}

// Compile-time assertion that the service satisfies the generated contract.
var _ pb.WafMigrationHTTPServer = (*WAFMigrationService)(nil)
