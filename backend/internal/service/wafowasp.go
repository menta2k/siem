package service

import (
	"context"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/crs"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
)

// Explaining a Cloudflare OWASP block by naming the rules behind it.
//
// Cloudflare reports "949110: Inbound Anomaly Score Exceeded" and stops there. That names
// the decision and hides the reasoning, so an operator looking at a false positive cannot
// tell whether to raise the threshold, exclude one rule, or accept the block. 949110 is
// the Core Rule Set's own number — Cloudflare's managed ruleset IS the CRS — so the same
// rules can be run here against the request the platform already stored, and the
// contributors named.
//
// It reports what matched. It does not recommend an exclusion: which rule to switch off is
// a decision with consequences, and it belongs to whoever owns them.

// OwaspEvaluator runs the Core Rule Set against a captured request.
type OwaspEvaluator interface {
	Evaluate(request crs.Request) (crs.Result, error)
}

// WithOwasp enables the OWASP explanation.
//
// Optional, like the expression evaluator, and for the same reason: a deployment without
// it keeps every migration page and refuses only this one panel, with a reason. It shares
// the payload reader and the adapters, which have to be configured for either to work.
func (s *WAFMigrationService) WithOwasp(evaluator OwaspEvaluator) *WAFMigrationService {
	s.owasp = evaluator
	return s
}

// ExplainOwasp reports which Core Rule Set rules a stored request matches.
func (s *WAFMigrationService) ExplainOwasp(
	ctx context.Context, req *pb.WafOwaspRequest,
) (*pb.WafOwaspResult, error) {
	if req.GetEventId() == "" {
		return nil, mw.ValidationFailed("an event id is required")
	}
	if s.owasp == nil || s.payloads == nil {
		// A configuration, not a fault. Failing the request would suggest the request was
		// the problem rather than the deployment.
		return &pb.WafOwaspResult{
			Available: false,
			Error:     "this deployment has no OWASP rule engine configured",
		}, nil
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	raw, err := s.payloads.GetRawPayload(ctx, req.GetEventId(), chdata.RawPayloadHint{
		ReceivedAt:   req.GetReceivedAt().AsTime(),
		SourceVendor: req.GetSourceVendor(),
	})
	if err != nil || len(raw.Payload) == 0 {
		// The request has aged past retention. Saying "no rule matched" here would be a
		// clean bill of health for a request nobody looked at.
		return &pb.WafOwaspResult{
			Available: false,
			Error: "the request as the vendor logged it is no longer retained, so there " +
				"is nothing to evaluate",
		}, nil
	}

	// The vendor that DELIVERED the bytes parses them, not the vendor the event is
	// attributed to: a DataDome verdict arrives inside a Cloudflare payload, and handing
	// those bytes to the wrong adapter returns nothing.
	vendor := req.GetSourceVendor()
	if vendor == "" {
		vendor = raw.Vendor
	}
	fields, _ := payloadFields(s.adapters, vendor, raw.Payload, nil)

	request, ok := crs.ParseTranscript(fields["request"])
	if !ok {
		return &pb.WafOwaspResult{
			Available: false,
			Error: "this vendor's log of the request does not include the request itself, " +
				"so there is nothing for the rules to read",
		}, nil
	}

	result, err := s.owasp.Evaluate(request)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return owaspResult(result), nil
}

// owaspResult renders a reading onto the wire.
func owaspResult(result crs.Result) *pb.WafOwaspResult {
	out := &pb.WafOwaspResult{
		Available:      true,
		Matched:        make([]*pb.WafOwaspMatch, 0, len(result.Matched)),
		BlockingScore:  uint32(clamp(result.BlockingScore)),
		DetectionScore: uint32(clamp(result.DetectionScore)),
		Threshold:      uint32(clamp(result.Threshold)),
		ParanoiaLevel:  uint32(clamp(result.ParanoiaLevel)),
		WouldBlock:     result.WouldBlock,
		BodyEvaluated:  uint32(clamp(result.BodyEvaluated)),
		BodyDeclared:   uint32(clamp(result.BodyDeclared)),
		BodyTruncated:  result.BodyTruncated,
		Notes:          result.Notes,
	}

	for _, match := range result.Matched {
		out.Matched = append(out.Matched, &pb.WafOwaspMatch{
			Id:       uint32(clamp(match.ID)),
			Message:  match.Message,
			Data:     match.Data,
			Severity: match.Severity,
			Phase:    uint32(clamp(match.Phase)),
			Category: match.Category,
			Score:    uint32(clamp(match.Score)),
			Artifact: match.Artifact,
		})
	}
	return out
}

// clamp keeps a count inside the range the wire type can carry.
//
// Every number here is a count or an identifier and cannot legitimately be negative, but
// the conversion is where a bug would become a wildly wrong number rather than an error.
func clamp(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
