package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/correlate/confidence"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
)

// maxCorrelatedPageSize caps a listing. Unbounded reads are rejected, not queued.
const (
	maxCorrelatedPageSize     = 200
	defaultCorrelatedPageSize = 50
)

// CorrelatedReader is the read surface this service needs.
//
// An interface rather than the repository itself so the contract test can drive the
// real handler — and therefore the real proto-to-JSON encoding the API actually
// emits — without standing up ClickHouse. A contract asserted against a hand-built
// response object is not asserting anything about the handler.
type CorrelatedReader interface {
	Get(ctx context.Context, correlationID uuid.UUID) (chdata.CorrelatedRequest, error)
	List(ctx context.Context, f chdata.CorrelatedFilter) ([]chdata.CorrelatedRequest, error)
}

// CorrelationService implements the Correlation proto service.
type CorrelationService struct {
	correlated CorrelatedReader
	// networks names the client's ASN on read. Optional: nil where the lookup is
	// disabled, in which case records carry the bare number.
	networks NetworkNamer
	// rules names the WAF rule each vendor reported. Optional in the same way.
	rules RuleNamer
}

// NewCorrelationService constructs the service.
func NewCorrelationService(
	correlated CorrelatedReader, networks NetworkNamer, rules RuleNamer,
) *CorrelationService {
	return &CorrelationService{correlated: correlated, networks: networks, rules: rules}
}

// GetCorrelatedRequest returns one correlated record with its full join provenance.
func (s *CorrelationService) GetCorrelatedRequest(
	ctx context.Context, req *pb.GetCorrelatedRequestRequest,
) (*pb.CorrelatedRequest, error) {
	correlationID, err := uuid.Parse(req.GetCorrelationId())
	if err != nil {
		return nil, mw.ValidationFailed("correlation_id must be a UUID")
	}

	record, err := s.correlated.Get(ctx, correlationID)
	switch {
	case errors.Is(err, chdata.ErrCorrelatedNotFound):
		return nil, mw.NotFound("correlated request")
	case err != nil:
		return nil, mw.Internal().WithCause(err)
	}
	out := toCorrelatedProto(record)
	nameClients(ctx, s.networks, out.GetClient())
	describeVerdicts(ctx, s.rules, []*pb.CorrelatedRequest{out})
	return out, nil
}

// ListCorrelatedRequests returns correlated records inside a time range.
func (s *CorrelationService) ListCorrelatedRequests(
	ctx context.Context, req *pb.ListCorrelatedRequestsRequest,
) (*pb.ListCorrelatedRequestsResponse, error) {
	from, to, err := correlatedRange(req.GetTimeRange())
	if err != nil {
		return nil, err
	}

	size := int(req.GetPage().GetLimit())
	switch {
	case size <= 0:
		size = defaultCorrelatedPageSize
	case size > maxCorrelatedPageSize:
		return nil, mw.ResultLimitExceeded(maxCorrelatedPageSize)
	}

	records, err := s.correlated.List(ctx, chdata.CorrelatedFilter{
		From:            from,
		To:              to,
		Confidence:      confidenceFromProto(req.GetConfidence()),
		OnlyDisagreeing: req.GetOnlyDisagreements(),
		MinVendorCount:  clampVendorCount(req.GetMinVendorCount()),
		Limit:           size,
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := &pb.ListCorrelatedRequestsResponse{
		Requests: make([]*pb.CorrelatedRequest, 0, len(records)),
		Page:     &pb.PageResponse{},
	}
	for _, record := range records {
		out.Requests = append(out.Requests, toCorrelatedProto(record))
	}
	// One lookup for the whole page, as in SearchEvents.
	nameClients(ctx, s.networks, correlatedClientsOf(out.GetRequests())...)
	describeVerdicts(ctx, s.rules, out.GetRequests())
	return out, nil
}

// correlatedRange validates the mandatory time bounds.
//
// Both ends are required because a correlated-request scan without them reads every
// partition the tenant has ever written, which cannot meet the latency budget and
// would be felt by every other tenant on the cluster.
func correlatedRange(r *pb.TimeRange) (time.Time, time.Time, error) {
	if r == nil || r.GetFrom() == nil || r.GetTo() == nil {
		return time.Time{}, time.Time{}, mw.TimeRangeRequired()
	}
	from, to := r.GetFrom().AsTime().UTC(), r.GetTo().AsTime().UTC()
	if !from.Before(to) {
		return time.Time{}, time.Time{}, mw.ValidationFailed("time_range.from must precede time_range.to")
	}
	return from, to, nil
}

// clampVendorCount saturates rather than wrapping: the column is a UInt8, and a
// nonsensical filter should narrow to nothing, not silently become zero.
func clampVendorCount(n uint32) uint8 {
	if n > 255 {
		return 255
	}
	return uint8(n)
}

func toCorrelatedProto(r chdata.CorrelatedRequest) *pb.CorrelatedRequest {
	out := &pb.CorrelatedRequest{
		CorrelationId:    r.CorrelationID.String(),
		WindowStart:      timestamppb.New(r.WindowStart),
		FirstEventTime:   timestamppb.New(r.FirstEventTime),
		LastEventTime:    timestamppb.New(r.LastEventTime),
		Client:           toClientProto(r),
		Request:          toRequestProto(r),
		VendorVerdicts:   toVendorVerdictsProto(r),
		VendorCount:      uint32(r.VendorCount),
		EventIds:         r.EventIDs,
		CombinedOutcome:  verdictToProto(r.CombinedOutcome),
		HasDisagreement:  r.HasDisagreement,
		DisagreementKind: disagreementToProto(r.DisagreementKind),
		JoinSignals:      joinSignalsToProto(r.JoinSignals),
		JoinTier:         uint32(r.JoinTier),
		Confidence:       confidenceToProto(r.Confidence),
		CandidateCount:   uint32(r.CandidateCount),
		Version:          r.Version,
		Amended:          r.Amended,
	}
	return out
}

func toClientProto(r chdata.CorrelatedRequest) *pb.ClientInfo {
	client := &pb.ClientInfo{
		IpShared: r.ClientIPShared,
		Asn:      r.ClientASN,
		Country:  r.ClientCountry,
	}
	if r.ClientIP != nil {
		client.Ip = r.ClientIP.String()
	}
	return client
}

func toRequestProto(r chdata.CorrelatedRequest) *pb.RequestInfo {
	return &pb.RequestInfo{
		Host:   r.RequestHost,
		Path:   r.RequestPath,
		Method: r.RequestMethod,
	}
}

// toVendorVerdictsProto rebuilds the per-vendor breakdown from the record's maps.
//
// The order follows the record's vendor list rather than Go's map iteration, so two
// reads of the same record return the same thing. A response that reshuffles itself
// between calls is unusable for both diffing and caching.
func toVendorVerdictsProto(r chdata.CorrelatedRequest) []*pb.VendorVerdict {
	out := make([]*pb.VendorVerdict, 0, len(r.Vendors))
	for _, vendor := range r.Vendors {
		verdict := &pb.VendorVerdict{
			Vendor:  vendorToProto(vendor),
			Verdict: verdictToProto(r.Verdicts[vendor]),
			RuleId:  r.RuleIDs[vendor],
		}
		if score, ok := r.Scores[vendor]; ok {
			verdict.Score = &score
		}
		out = append(out, verdict)
	}
	return out
}

func verdictToProto(v string) pb.Verdict {
	switch v {
	case vendors.VerdictAllowed:
		return pb.Verdict_VERDICT_ALLOWED
	case vendors.VerdictBlocked:
		return pb.Verdict_VERDICT_BLOCKED
	case vendors.VerdictChallenged:
		return pb.Verdict_VERDICT_CHALLENGED
	case vendors.VerdictRateLimited:
		return pb.Verdict_VERDICT_RATE_LIMITED
	case vendors.VerdictMonitored:
		return pb.Verdict_VERDICT_MONITORED
	case vendors.VerdictUnknown:
		return pb.Verdict_VERDICT_UNKNOWN
	default:
		return pb.Verdict_VERDICT_UNSPECIFIED
	}
}

func confidenceToProto(c string) pb.Confidence {
	switch confidence.Level(c) {
	case confidence.High:
		return pb.Confidence_CONFIDENCE_HIGH
	case confidence.Medium:
		return pb.Confidence_CONFIDENCE_MEDIUM
	case confidence.Low:
		return pb.Confidence_CONFIDENCE_LOW
	default:
		return pb.Confidence_CONFIDENCE_UNSPECIFIED
	}
}

func confidenceFromProto(c pb.Confidence) string {
	switch c {
	case pb.Confidence_CONFIDENCE_HIGH:
		return string(confidence.High)
	case pb.Confidence_CONFIDENCE_MEDIUM:
		return string(confidence.Medium)
	case pb.Confidence_CONFIDENCE_LOW:
		return string(confidence.Low)
	case pb.Confidence_CONFIDENCE_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func disagreementToProto(kind string) pb.DisagreementKind {
	switch normalize.DisagreementKind(kind) {
	case normalize.DisagreementNone:
		return pb.DisagreementKind_DISAGREEMENT_KIND_NONE
	case normalize.DisagreementAllowVsBlock:
		return pb.DisagreementKind_DISAGREEMENT_KIND_ALLOW_VS_BLOCK
	case normalize.DisagreementAllowVsChallenge:
		return pb.DisagreementKind_DISAGREEMENT_KIND_ALLOW_VS_CHALLENGE
	case normalize.DisagreementScoreConflict:
		return pb.DisagreementKind_DISAGREEMENT_KIND_SCORE_CONFLICT
	default:
		return pb.DisagreementKind_DISAGREEMENT_KIND_UNSPECIFIED
	}
}

func joinSignalsToProto(signals []string) []pb.JoinSignal {
	out := make([]pb.JoinSignal, 0, len(signals))
	for _, signal := range signals {
		switch keys.Signal(signal) {
		case keys.SignalVendorRequestID:
			out = append(out, pb.JoinSignal_JOIN_SIGNAL_VENDOR_REQUEST_ID)
		case keys.SignalIPHostPathMethod:
			out = append(out, pb.JoinSignal_JOIN_SIGNAL_IP_HOST_PATH_METHOD)
		case keys.SignalTimeWindow:
			out = append(out, pb.JoinSignal_JOIN_SIGNAL_TIME_WINDOW)
		}
	}
	return out
}
