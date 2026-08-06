package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/vendors"
)

// FeedsService implements the Feeds proto service.
type FeedsService struct {
	feeds    *chdata.FeedRepo
	events   *chdata.EventRepo
	health   *chdata.HealthRepo
	secrets  secrets.Store
	auditLog *chdata.AuditRepo
	registry *vendors.Registry
}

// NewFeedsService constructs the service.
func NewFeedsService(
	feeds *chdata.FeedRepo, events *chdata.EventRepo, health *chdata.HealthRepo,
	secretStore secrets.Store, auditLog *chdata.AuditRepo, registry *vendors.Registry,
) *FeedsService {
	return &FeedsService{
		feeds: feeds, events: events, health: health,
		secrets: secretStore, auditLog: auditLog, registry: registry,
	}
}

// ListFeeds returns the tenant's feeds with their current health.
func (s *FeedsService) ListFeeds(
	ctx context.Context, _ *pb.ListFeedsRequest,
) (*pb.ListFeedsResponse, error) {
	feeds, err := s.feeds.List(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// Health is fetched in one query for all feeds rather than per feed: the list view
	// is the most-loaded page in the console, and N+1 here would be felt immediately.
	health, err := s.health.ListFeedHealth(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := make([]*pb.Feed, 0, len(feeds))
	for _, feed := range feeds {
		h := health[feed.ID]
		out = append(out, toFeedProto(feed, &h))
	}
	return &pb.ListFeedsResponse{Feeds: out}, nil
}

// GetFeed returns one feed.
func (s *FeedsService) GetFeed(ctx context.Context, req *pb.GetFeedRequest) (*pb.Feed, error) {
	feedID, err := parseUUID(req.GetFeedId(), "feed id")
	if err != nil {
		return nil, err
	}

	feed, err := s.feeds.Get(ctx, feedID)
	if err != nil {
		return nil, notFoundOr(err, "feed")
	}

	health, err := s.health.GetFeedHealth(ctx, feedID)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return toFeedProto(feed, &health), nil
}

// CreateFeed stores a feed and its credential.
//
// The credential is written to the secret manager and only its reference is persisted
// on the feed row. It is never returned by this or any other operation.
func (s *FeedsService) CreateFeed(
	ctx context.Context, req *pb.CreateFeedRequest,
) (*pb.Feed, error) {
	vendorName, err := s.validateCreate(req)
	if err != nil {
		return nil, err
	}

	credentialRef, signingRef, err := s.storeNewSecrets(ctx, req)
	if err != nil {
		return nil, err
	}

	created, err := s.feeds.Create(ctx, chdata.Feed{
		Vendor:            vendorName,
		Name:              req.GetName(),
		Delivery:          deliveryFromProto(req.GetDeliveryMode()),
		Enabled:           true,
		CredentialRef:     credentialRef,
		SigningSecretRef:  signingRef,
		PullConfig:        orDefault(req.GetPullConfig(), "{}"),
		QuotaEventsPerSec: orDefaultUint32(req.GetQuotaEventsPerSec(), 5000),
		QuotaBytesPerDay:  orDefaultUint64(req.GetQuotaBytesPerDay(), 100<<30),
	})
	if err != nil {
		// The secrets are orphaned if the feed row fails, so they are cleaned up
		// rather than left behind holding a live credential.
		_ = s.secrets.Delete(ctx, credentialRef)
		if signingRef != "" {
			_ = s.secrets.Delete(ctx, signingRef)
		}
		if errors.Is(err, chdata.ErrFeedNameTaken) {
			return nil, mw.Conflict("a feed with that name already exists")
		}
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionFeedCreate, TargetType: "feed", TargetID: created.ID.String(),
		AfterValue: auditableFeed(created), Result: audit.ResultSuccess,
	})

	return toFeedProto(created, nil), nil
}

// validateCreate checks a create request and resolves its vendor.
func (s *FeedsService) validateCreate(req *pb.CreateFeedRequest) (string, error) {
	vendorName, err := s.validateVendor(req.GetVendor())
	if err != nil {
		return "", err
	}
	if req.GetName() == "" {
		return "", mw.ValidationFailed("a feed name is required")
	}
	if req.GetCredential() == "" {
		return "", mw.ValidationFailed("a credential is required to create a feed")
	}
	if err := validatePullConfig(req.GetDeliveryMode(), req.GetPullConfig()); err != nil {
		return "", err
	}
	return vendorName, nil
}

// storeNewSecrets writes the credential and optional signing key, returning refs.
func (s *FeedsService) storeNewSecrets(
	ctx context.Context, req *pb.CreateFeedRequest,
) (credentialRef, signingRef string, err error) {
	credentialRef, err = s.secrets.Put(ctx, "feed-credential", req.GetCredential())
	if err != nil {
		return "", "", mw.Internal().WithCause(err)
	}

	if req.GetSigningSecret() != "" {
		signingRef, err = s.secrets.Put(ctx, "feed-signing", req.GetSigningSecret())
		if err != nil {
			_ = s.secrets.Delete(ctx, credentialRef)
			return "", "", mw.Internal().WithCause(err)
		}
	}
	return credentialRef, signingRef, nil
}

// UpdateFeed changes a feed's configuration, rotating credentials when supplied.
func (s *FeedsService) UpdateFeed(
	ctx context.Context, req *pb.UpdateFeedRequest,
) (*pb.Feed, error) {
	feedID, err := parseUUID(req.GetFeedId(), "feed id")
	if err != nil {
		return nil, err
	}

	current, err := s.feeds.Get(ctx, feedID)
	if err != nil {
		return nil, notFoundOr(err, "feed")
	}
	before := auditableFeed(current)

	credentialRef, signingRef, err := s.rotateSecrets(ctx, current, req)
	if err != nil {
		return nil, err
	}

	updated, err := s.feeds.Update(ctx, feedID, func(f chdata.Feed) chdata.Feed {
		if req.Name != nil {
			f.Name = req.GetName()
		}
		if req.Enabled != nil {
			f.Enabled = req.GetEnabled()
		}
		if req.PullConfig != nil {
			f.PullConfig = req.GetPullConfig()
		}
		if req.QuotaEventsPerSec != nil {
			f.QuotaEventsPerSec = req.GetQuotaEventsPerSec()
		}
		if req.QuotaBytesPerDay != nil {
			f.QuotaBytesPerDay = req.GetQuotaBytesPerDay()
		}
		f.CredentialRef, f.SigningSecretRef = credentialRef, signingRef
		return f
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionFeedUpdate, TargetType: "feed", TargetID: feedID.String(),
		BeforeValue: before, AfterValue: auditableFeed(updated), Result: audit.ResultSuccess,
	})

	return toFeedProto(updated, nil), nil
}

// rotateSecrets stores replacement credentials, returning the references to persist.
//
// The old secret is deleted only after the new one is stored, so a failure mid-way
// leaves the feed authenticating with its existing credential rather than with none.
func (s *FeedsService) rotateSecrets(
	ctx context.Context, current chdata.Feed, req *pb.UpdateFeedRequest,
) (credentialRef, signingRef string, err error) {
	credentialRef, signingRef = current.CredentialRef, current.SigningSecretRef

	if req.Credential != nil && req.GetCredential() != "" {
		newRef, putErr := s.secrets.Put(ctx, "feed-credential", req.GetCredential())
		if putErr != nil {
			return "", "", mw.Internal().WithCause(putErr)
		}
		_ = s.secrets.Delete(ctx, credentialRef)
		credentialRef = newRef
	}

	if req.SigningSecret != nil {
		if req.GetSigningSecret() == "" {
			// An explicit empty value disables signing.
			_ = s.secrets.Delete(ctx, signingRef)
			signingRef = ""
		} else {
			newRef, putErr := s.secrets.Put(ctx, "feed-signing", req.GetSigningSecret())
			if putErr != nil {
				return "", "", mw.Internal().WithCause(putErr)
			}
			_ = s.secrets.Delete(ctx, signingRef)
			signingRef = newRef
		}
	}

	return credentialRef, signingRef, nil
}

// DeleteFeed soft-disables a feed.
//
// Ingested data is deliberately untouched: a customer removing a feed is saying "stop
// accepting new events", not "destroy the evidence I already collected". Deletion of
// stored events happens only through retention or an explicitly audited purge.
func (s *FeedsService) DeleteFeed(
	ctx context.Context, req *pb.DeleteFeedRequest,
) (*pb.DeleteFeedResponse, error) {
	feedID, err := parseUUID(req.GetFeedId(), "feed id")
	if err != nil {
		return nil, err
	}

	current, err := s.feeds.Get(ctx, feedID)
	if err != nil {
		return nil, notFoundOr(err, "feed")
	}

	if _, err := s.feeds.Update(ctx, feedID, func(f chdata.Feed) chdata.Feed {
		f.Enabled = false
		return f
	}); err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// The credential is revoked even though the row survives, so a disabled feed
	// cannot be reactivated by a vendor still holding the old token.
	_ = s.secrets.Delete(ctx, current.CredentialRef)
	_ = s.secrets.Delete(ctx, current.SigningSecretRef)

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionFeedDelete, TargetType: "feed", TargetID: feedID.String(),
		BeforeValue: auditableFeed(current), Result: audit.ResultSuccess,
		Detail: "feed disabled; ingested data retained under the tenant's retention policy",
	})

	return &pb.DeleteFeedResponse{}, nil
}

// TestFeed reports whether a feed's credential resolves and its config is usable.
func (s *FeedsService) TestFeed(
	ctx context.Context, req *pb.TestFeedRequest,
) (*pb.TestFeedResponse, error) {
	feedID, err := parseUUID(req.GetFeedId(), "feed id")
	if err != nil {
		return nil, err
	}

	feed, err := s.feeds.Get(ctx, feedID)
	if err != nil {
		return nil, notFoundOr(err, "feed")
	}

	// A failing check is the ANSWER, not a request failure: the caller asked "is this
	// feed working" and gets "no, and here is why". Returning an error would surface
	// as a 500 and tell the operator nothing actionable.
	if _, err := s.secrets.Resolve(ctx, feed.CredentialRef); err != nil {
		return &pb.TestFeedResponse{ //nolint:nilerr // a failed check is the answer
			Reachable: false, CredentialValid: false,
			Detail: "the stored credential could not be resolved; re-enter it to repair the feed",
		}, nil
	}

	if _, err := s.registry.Get(feed.Vendor); err != nil {
		return &pb.TestFeedResponse{ //nolint:nilerr // a failed check is the answer
			Reachable: false, CredentialValid: true,
			Detail: fmt.Sprintf("no adapter is registered for vendor %q", feed.Vendor),
		}, nil
	}

	if feed.Delivery == chdata.DeliveryPull {
		if err := validatePullConfigJSON(feed.PullConfig); err != nil {
			return &pb.TestFeedResponse{ //nolint:nilerr // a failed check is the answer
				Reachable: false, CredentialValid: true,
				Detail: "the pull configuration is not valid JSON",
			}, nil
		}
	}

	return &pb.TestFeedResponse{
		Reachable: true, CredentialValid: true,
		Detail: "the feed is configured correctly and ready to receive events",
	}, nil
}

// GetFeedHealth returns the feed's current health.
func (s *FeedsService) GetFeedHealth(
	ctx context.Context, req *pb.GetFeedHealthRequest,
) (*pb.FeedHealth, error) {
	feedID, err := parseUUID(req.GetFeedId(), "feed id")
	if err != nil {
		return nil, err
	}
	if _, err := s.feeds.Get(ctx, feedID); err != nil {
		return nil, notFoundOr(err, "feed")
	}

	health, err := s.health.GetFeedHealth(ctx, feedID)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return toHealthProto(feedID, health), nil
}

// ListRejectedEvents returns dead-lettered events for a feed.
func (s *FeedsService) ListRejectedEvents(
	ctx context.Context, req *pb.ListRejectedEventsRequest,
) (*pb.ListRejectedEventsResponse, error) {
	feedID, err := parseUUID(req.GetFeedId(), "feed id")
	if err != nil {
		return nil, err
	}
	from, to, err := requireTimeRange(req.GetRange())
	if err != nil {
		return nil, err
	}

	filter := chdata.RejectedFilter{
		FeedID: feedID, From: from, To: to,
		Limit: cappedLimit(req.GetPage().GetLimit()),
	}
	if req.ReasonCode != nil {
		filter.ReasonCode = req.GetReasonCode()
	}

	rejected, err := s.events.ListRejected(ctx, filter)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := make([]*pb.RejectedEvent, 0, len(rejected))
	for _, entry := range rejected {
		out = append(out, &pb.RejectedEvent{
			RejectedAt:   timestamppb.New(entry.RejectedAt),
			Vendor:       vendorToProto(entry.Vendor),
			ReasonCode:   entry.ReasonCode,
			ReasonDetail: entry.ReasonDetail,
			// The payload is attacker-controlled. It is returned verbatim because an
			// operator needs to see exactly what the vendor sent, and the console
			// renders it as inert text.
			Payload: string(entry.Payload),
			BatchId: entry.BatchID.String(),
		})
	}

	return &pb.ListRejectedEventsResponse{
		Events: out,
		Page:   &pb.PageResponse{Total: int64(len(out)), TotalIsEstimate: false},
	}, nil
}

func (s *FeedsService) validateVendor(v pb.Vendor) (string, error) {
	name := vendorFromProto(v)
	if name == "" {
		return "", mw.ValidationFailed("a supported vendor is required")
	}
	if _, err := s.registry.Get(name); err != nil {
		return "", mw.ValidationFailed(fmt.Sprintf("vendor %q is not supported", name))
	}
	return name, nil
}

// ---------------------------------------------------------------- mapping

// auditableFeed renders a feed for the audit trail WITHOUT its credential references.
//
// The references are not secrets, but recording them would let anyone with audit
// access correlate a feed to a secret-manager key, which is needless exposure in a
// record that is retained for a year and readable by auditors.
func auditableFeed(f chdata.Feed) string {
	encoded, err := json.Marshal(map[string]any{
		"vendor":               f.Vendor,
		"name":                 f.Name,
		"delivery_mode":        f.Delivery,
		"enabled":              f.Enabled,
		"quota_events_per_sec": f.QuotaEventsPerSec,
		"quota_bytes_per_day":  f.QuotaBytesPerDay,
		"credential_set":       f.CredentialRef != "",
		"signing_set":          f.SigningSecretRef != "",
	})
	if err != nil {
		return ""
	}
	return string(encoded)
}

func toFeedProto(f chdata.Feed, health *chdata.FeedHealth) *pb.Feed {
	out := &pb.Feed{
		FeedId:       f.ID.String(),
		Vendor:       vendorToProto(f.Vendor),
		Name:         f.Name,
		DeliveryMode: deliveryToProto(f.Delivery),
		Enabled:      f.Enabled,
		// The credential itself is never returned — only whether one is configured.
		CredentialConfigured: f.CredentialRef != "",
		SigningConfigured:    f.SigningSecretRef != "",
		PullConfig:           f.PullConfig,
		QuotaEventsPerSec:    f.QuotaEventsPerSec,
		QuotaBytesPerDay:     f.QuotaBytesPerDay,
		CreatedAt:            timestamppb.New(f.CreatedAt),
		UpdatedAt:            timestamppb.New(f.UpdatedAt),
	}
	if health != nil {
		out.Health = toHealthProto(f.ID, *health)
	}
	return out
}

func toHealthProto(feedID uuid.UUID, h chdata.FeedHealth) *pb.FeedHealth {
	out := &pb.FeedHealth{
		FeedId:                  feedID.String(),
		Silent:                  h.Silent,
		EventsPerSec:            h.EventsPerSec,
		EventsReceived_1H:       h.EventsReceived1h,
		EventsRejected_1H:       h.EventsRejected1h,
		DuplicatesSuppressed_1H: h.DuplicatesSuppressed,
		BytesReceived_1H:        h.BytesReceived1h,
		MaxIngestLagMs:          h.MaxIngestLagMS,
		CredentialValid:         h.CredentialValid,
		SchemaDriftWarning:      h.SchemaDriftWarning(),
	}
	if !h.LastEventAt.IsZero() {
		out.LastEventAt = timestamppb.New(h.LastEventAt)
	}
	return out
}

func vendorFromProto(v pb.Vendor) string {
	switch v {
	case pb.Vendor_VENDOR_CLOUDFLARE:
		return vendors.Cloudflare
	case pb.Vendor_VENDOR_F5:
		return vendors.F5
	case pb.Vendor_VENDOR_DATADOME:
		return vendors.DataDome
	case pb.Vendor_VENDOR_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func vendorToProto(name string) pb.Vendor {
	switch name {
	case vendors.Cloudflare:
		return pb.Vendor_VENDOR_CLOUDFLARE
	case vendors.F5:
		return pb.Vendor_VENDOR_F5
	case vendors.DataDome:
		return pb.Vendor_VENDOR_DATADOME
	default:
		return pb.Vendor_VENDOR_UNSPECIFIED
	}
}

func deliveryFromProto(mode pb.DeliveryMode) string {
	if mode == pb.DeliveryMode_DELIVERY_MODE_PULL {
		return chdata.DeliveryPull
	}
	return chdata.DeliveryPush
}

func deliveryToProto(mode string) pb.DeliveryMode {
	if mode == chdata.DeliveryPull {
		return pb.DeliveryMode_DELIVERY_MODE_PULL
	}
	return pb.DeliveryMode_DELIVERY_MODE_PUSH
}

// ---------------------------------------------------------------- helpers

func parseUUID(value, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, mw.ValidationFailed(fmt.Sprintf("the %s is not a valid identifier", field))
	}
	return id, nil
}

func notFoundOr(err error, what string) error {
	if errors.Is(err, chdata.ErrNotFound) {
		return mw.NotFound(what)
	}
	return mw.Internal().WithCause(err)
}

// requireTimeRange enforces the mandatory bounds on every event-data read.
func requireTimeRange(r *pb.TimeRange) (from, to time.Time, err error) {
	if r == nil || r.GetFrom() == nil || r.GetTo() == nil {
		return time.Time{}, time.Time{}, mw.TimeRangeRequired()
	}
	from, to = r.GetFrom().AsTime(), r.GetTo().AsTime()
	if !from.Before(to) {
		return time.Time{}, time.Time{}, mw.ValidationFailed("the time range must start before it ends")
	}
	return from, to, nil
}

func cappedLimit(requested int32) int32 {
	const maxLimit = 1000
	if requested <= 0 {
		return 100
	}
	if requested > maxLimit {
		return maxLimit
	}
	return requested
}

func validatePullConfig(mode pb.DeliveryMode, config string) error {
	if mode != pb.DeliveryMode_DELIVERY_MODE_PULL {
		return nil
	}
	if config == "" {
		return mw.ValidationFailed("pull delivery requires a pull configuration")
	}
	if err := validatePullConfigJSON(config); err != nil {
		return mw.ValidationFailed("the pull configuration is not valid JSON")
	}
	return nil
}

func validatePullConfigJSON(config string) error {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		return fmt.Errorf("parse pull config: %w", err)
	}
	return nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func orDefaultUint32(value, fallback uint32) uint32 {
	if value == 0 {
		return fallback
	}
	return value
}

func orDefaultUint64(value, fallback uint64) uint64 {
	if value == 0 {
		return fallback
	}
	return value
}

// Compile-time assertion that the service satisfies the generated contract.
var _ pb.FeedsHTTPServer = (*FeedsService)(nil)
