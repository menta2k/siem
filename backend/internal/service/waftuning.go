package service

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
)

// WAFTuningReader is the storage surface the tuning views read through.
type WAFTuningReader interface {
	RuleProfile(
		ctx context.Context, q chdata.DashboardQuery, filter chdata.WAFRuleFilter,
	) ([]chdata.WAFRuleProfile, error)
	RulePaths(
		ctx context.Context, ruleID string, q chdata.DashboardQuery,
	) ([]chdata.WAFPathCount, error)
	RuleSamples(
		ctx context.Context, ruleID string, q chdata.DashboardQuery,
	) ([]chdata.WAFRuleSample, error)
	CoverageGaps(ctx context.Context, q chdata.DashboardQuery) ([]chdata.WAFCoverageGap, error)
	Corroboration(
		ctx context.Context, ruleID string, q chdata.DashboardQuery,
	) (chdata.WAFCorroboration, error)
}

// WAFTuningService implements the WafTuning proto service.
//
// It reports evidence and never produces configuration. Which rules to enforce and
// which to except is a decision with consequences the platform does not carry, so the
// job here is to make the numbers behind that decision easy to read and hard to
// misread — particularly the attack score, whose scale runs backwards.
type WAFTuningService struct {
	waf    WAFTuningReader
	limits query.Limits
	// rules names a rule id, through the same resolver the rest of the console uses.
	// Optional: a deployment with no Cloudflare token gets bare ids.
	rules RuleNamer
	now   func() time.Time
}

// NewWAFTuningService constructs the service.
func NewWAFTuningService(
	waf WAFTuningReader, limits query.Limits, rules RuleNamer,
) *WAFTuningService {
	return &WAFTuningService{waf: waf, limits: limits, rules: rules, now: time.Now}
}

// tuningQuery validates the range and limit the way every panel does.
func (s *WAFTuningService) tuningQuery(
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

// GetRuleProfile returns every rule that fired, split by host, action and source.
func (s *WAFTuningService) GetRuleProfile(
	ctx context.Context, req *pb.WafTuningRequest,
) (*pb.WafRuleProfilePanel, error) {
	q, err := s.tuningQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	profiles, err := s.waf.RuleProfile(ctx, q, chdata.WAFRuleFilter{
		Action:  req.GetAction(),
		Reading: req.GetReading(),
	})
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.WafRuleProfilePanel{Rules: make([]*pb.WafRuleProfile, 0, len(profiles))}
	for _, p := range profiles {
		out.Rules = append(out.Rules, &pb.WafRuleProfile{
			RuleId:           p.RuleID,
			RequestHost:      p.RequestHost,
			Action:           p.Action,
			Source:           p.Source,
			Events:           p.Events,
			AttackEvents:     p.AttackEvents,
			SuspiciousEvents: p.SuspiciousEvents,
			CleanEvents:      p.CleanEvents,
			MeanScore:        p.MeanScore,
			Reading:          p.Reading,
		})
	}
	// One lookup for the whole page, matching the other panels: resolving per row turns
	// one query into fifty.
	describeWAFRules(ctx, s.rules, out.Rules)
	return out, nil
}

// GetRulePaths returns the URLs one rule matched on.
func (s *WAFTuningService) GetRulePaths(
	ctx context.Context, req *pb.WafRulePathsRequest,
) (*pb.WafRulePathsPanel, error) {
	if req.GetRuleId() == "" {
		return nil, mw.ValidationFailed("a rule id is required")
	}
	q, err := s.tuningQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	paths, err := s.waf.RulePaths(ctx, req.GetRuleId(), q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.WafRulePathsPanel{Paths: make([]*pb.WafPathCount, 0, len(paths))}
	for _, p := range paths {
		out.Paths = append(out.Paths, &pb.WafPathCount{
			RequestHost: p.RequestHost,
			RequestPath: p.RequestPath,
			Events:      p.Events,
			MeanScore:   p.MeanScore,
		})
	}
	return out, nil
}

// GetRuleSamples returns individual requests one rule matched.
func (s *WAFTuningService) GetRuleSamples(
	ctx context.Context, req *pb.WafRulePathsRequest,
) (*pb.WafRuleSamplePanel, error) {
	if req.GetRuleId() == "" {
		return nil, mw.ValidationFailed("a rule id is required")
	}
	q, err := s.tuningQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	samples, err := s.waf.RuleSamples(ctx, req.GetRuleId(), q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.WafRuleSamplePanel{Samples: make([]*pb.WafRuleSample, 0, len(samples))}
	for _, sample := range samples {
		item := &pb.WafRuleSample{
			EventId:       sample.EventID,
			EventTime:     timestamppb.New(sample.EventTime),
			Country:       sample.Country,
			RequestHost:   sample.RequestHost,
			RequestPath:   sample.RequestPath,
			RequestQuery:  sample.RequestQuery,
			RequestMethod: sample.RequestMethod,
			HttpStatus:    uint32(sample.HTTPStatus),
			AttackScore:   uint32(sample.AttackScore),
			Verdict:       sample.Verdict,
		}
		// Absent rather than "::" for the events that carry no client address — the
		// DataDome subrequests do not, and a rendered zero address reads as a real one.
		if sample.ClientIP != nil {
			item.ClientIp = sample.ClientIP.String()
		}
		out.Samples = append(out.Samples, item)
	}
	return out, nil
}

// GetCoverageGaps returns hosts taking attack-scored traffic that no rule matched.
func (s *WAFTuningService) GetCoverageGaps(
	ctx context.Context, req *pb.WafTuningRequest,
) (*pb.WafCoverageGapPanel, error) {
	q, err := s.tuningQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	gaps, err := s.waf.CoverageGaps(ctx, q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.WafCoverageGapPanel{Gaps: make([]*pb.WafCoverageGap, 0, len(gaps))}
	for _, g := range gaps {
		out.Gaps = append(out.Gaps, &pb.WafCoverageGap{
			RequestHost:      g.RequestHost,
			Events:           g.Events,
			AttackEvents:     g.AttackEvents,
			SuspiciousEvents: g.SuspiciousEvents,
		})
	}
	return out, nil
}

// GetCorroboration reports what the other vendors made of one rule's requests.
func (s *WAFTuningService) GetCorroboration(
	ctx context.Context, req *pb.WafRulePathsRequest,
) (*pb.WafCorroboration, error) {
	if req.GetRuleId() == "" {
		return nil, mw.ValidationFailed("a rule id is required")
	}
	q, err := s.tuningQuery(req.GetTimeRange(), req.GetLimit())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	c, err := s.waf.Corroboration(ctx, req.GetRuleId(), q)
	if err != nil {
		return nil, query.TranslateError(err)
	}

	return &pb.WafCorroboration{
		RuleId:            c.RuleID,
		Correlated:        c.Correlated,
		ConfirmedByOthers: c.ConfirmedByOthers,
		AllowedByOthers:   c.AllowedByOthers,
	}, nil
}

// describeWAFRules resolves rule ids to names in one lookup for the whole page.
func describeWAFRules(ctx context.Context, namer RuleNamer, rules []*pb.WafRuleProfile) {
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
var _ pb.WafTuningHTTPServer = (*WAFTuningService)(nil)
