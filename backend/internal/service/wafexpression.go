package service

import (
	"context"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/wirefilter"
)

// Testing a candidate Cloudflare rule against requests the platform already holds.
//
// Stage 1 of the migration asks an operator to write a rule for traffic Cloudflare cannot
// see. Until this existed, finding out whether the rule works meant deploying it in log
// mode and waiting — and a mistake cost a day: one rule differed from a working one by a
// single backslash and matched nothing while looking correct.
//
// Nothing here decides whether an expression is GOOD. It reports which of the group's
// requests it would catch, and is careful about the ones it cannot answer for.

// ExpressionEvaluator runs an expression against captured requests.
type ExpressionEvaluator interface {
	Configured() bool
	Evaluate(
		ctx context.Context, expression string, requests []wirefilter.Request,
	) (wirefilter.Result, error)
}

// RawPayloadReader fetches the vendor's own transcript of one event.
type RawPayloadReader interface {
	GetRawPayload(
		ctx context.Context, eventID string, hint chdata.RawPayloadHint,
	) (chdata.RawPayload, error)
}

// maxExpressionRequests caps how many of a group's requests one test runs against.
//
// Twenty is enough to tell a rule that works from one that does not, and small enough that
// the answer arrives while the operator is still looking at it. A rule that matches none of
// twenty is not going to be rescued by the twenty-first.
const maxExpressionRequests = 20

// EvaluateExpression reports which of a group's requests a candidate rule would catch.
func (s *WAFMigrationService) EvaluateExpression(
	ctx context.Context, req *pb.WafExpressionRequest,
) (*pb.WafExpressionResult, error) {
	if req.GetExpression() == "" {
		return nil, mw.ValidationFailed("an expression is required")
	}
	if req.GetViolation() == "" && req.GetRuleId() == "" {
		return nil, mw.ValidationFailed("a violation or a rule id is required")
	}
	if s.evaluator == nil || !s.evaluator.Configured() {
		// A deployment without an evaluator is a configuration, not a fault, and saying so
		// is the answer. Failing would suggest the expression was the problem.
		return nil, mw.ValidationFailed(
			"no expression evaluator is configured for this deployment")
	}

	q, err := s.migrationQuery(req.GetTimeRange(), maxExpressionRequests)
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
	if len(samples) == 0 {
		// No requests is not a failed test. The group's evidence has aged out, or the
		// range holds none — either way the expression has not been judged.
		return &pb.WafExpressionResult{Valid: true}, nil
	}

	requests, paths := s.captureRequests(ctx, samples)
	result, err := s.evaluator.Evaluate(ctx, req.GetExpression(), requests)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return expressionResult(result, paths), nil
}

// samplePath is what a verdict is shown against: the request, not just its id.
type samplePath struct {
	path  string
	query string
}

// captureRequests turns the group's samples into evaluator input.
//
// A sample whose raw payload has expired is DROPPED rather than sent with an empty body: an
// expression matching on the body would miss it, and that miss would read as evidence about
// the rule when it is really evidence about retention.
func (s *WAFMigrationService) captureRequests(
	ctx context.Context, samples []chdata.WAFMigrationSample,
) ([]wirefilter.Request, map[string]samplePath) {
	requests := make([]wirefilter.Request, 0, len(samples))
	paths := make(map[string]samplePath, len(samples))

	for _, sample := range samples {
		raw, err := s.payloads.GetRawPayload(ctx, sample.F5EventID, chdata.RawPayloadHint{
			ReceivedAt:   sample.ReceivedAt,
			SourceVendor: sample.SourceVendor,
		})
		if err != nil || len(raw.Payload) == 0 {
			continue
		}

		// The vendor that DELIVERED the bytes parses them, not the vendor the event is
		// attributed to. They differ whenever one vendor's payload carries another's
		// verdict, and handing the bytes to the wrong adapter returns nothing.
		vendor := sample.SourceVendor
		if vendor == "" {
			vendor = vendors.F5
		}
		fields, _ := payloadFields(s.adapters, vendor, raw.Payload, nil)

		captured := wirefilter.CapturedRequest{
			EventID:   sample.F5EventID,
			Host:      sample.RequestHost,
			Method:    sample.RequestMethod,
			Path:      sample.RequestPath,
			Query:     sample.RequestQuery,
			UserAgent: sample.UserAgent,
			Raw:       fields["request"],
		}
		if sample.ClientIP != nil {
			captured.ClientIP = sample.ClientIP.String()
		}

		requests = append(requests, captured.Fields())
		paths[sample.F5EventID] = samplePath{path: sample.RequestPath, query: sample.RequestQuery}
	}
	return requests, paths
}

// expressionResult renders the evaluator's reply onto the wire.
func expressionResult(
	result wirefilter.Result, paths map[string]samplePath,
) *pb.WafExpressionResult {
	out := &pb.WafExpressionResult{
		Valid:             result.Valid,
		Error:             result.Error,
		UnavailableFields: result.UnavailableFields,
	}
	if !result.Valid {
		// A refused expression has no verdicts, and reporting "0 of 20 matched" beside the
		// reason would read as a result rather than as a question that was never asked.
		return out
	}

	out.Outcomes = make([]*pb.WafExpressionOutcome, 0, len(result.Outcomes))
	for _, outcome := range result.Outcomes {
		out.Tested++
		if outcome.Matched {
			out.Matched++
		}
		if outcome.Caveat != "" {
			out.Uncertain++
		}

		out.Outcomes = append(out.Outcomes, &pb.WafExpressionOutcome{
			EventId:      outcome.ID,
			RequestPath:  paths[outcome.ID].path,
			RequestQuery: paths[outcome.ID].query,
			Matched:      outcome.Matched,
			Caveat:       outcome.Caveat,
		})
	}
	return out
}
