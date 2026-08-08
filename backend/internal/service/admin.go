package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
	"github.com/menta2k/siem/internal/auth"
	"github.com/menta2k/siem/internal/correlate"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/ingest/filter"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/retention"
)

// Purger performs the audited explicit deletion.
type Purger interface {
	Purge(ctx context.Context, req retention.PurgeRequest) error
}

// SettingsInvalidator drops a tenant's cached correlation settings.
//
// Without this a settings change waits out the cache TTL before taking effect, and an
// operator who changed the correlation window watches nothing happen and changes it
// again.
type SettingsInvalidator interface {
	Invalidate(tenantID uuid.UUID)
}

// AdminService implements the Admin proto service.
type AdminService struct {
	users       *chdata.UserRepo
	tenants     *chdata.TenantRepo
	auditLog    *chdata.AuditRepo
	purger      Purger
	invalidator SettingsInvalidator
	now         func() time.Time
}

// NewAdminService constructs the service.
func NewAdminService(
	users *chdata.UserRepo, tenants *chdata.TenantRepo, auditLog *chdata.AuditRepo,
	purger Purger, invalidator SettingsInvalidator,
) *AdminService {
	return &AdminService{
		users: users, tenants: tenants, auditLog: auditLog,
		purger: purger, invalidator: invalidator, now: time.Now,
	}
}

// ---------------------------------------------------------------- users

// ListUsers returns the tenant's users.
func (s *AdminService) ListUsers(
	ctx context.Context, _ *pb.ListUsersRequest,
) (*pb.ListUsersResponse, error) {
	users, err := s.users.List(ctx, 500)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	out := &pb.ListUsersResponse{Users: make([]*pb.UserProfile, 0, len(users))}
	for _, user := range users {
		out.Users = append(out.Users, toUserProfile(user, tenant))
	}
	return out, nil
}

// CreateUser adds a user to the tenant.
func (s *AdminService) CreateUser(
	ctx context.Context, req *pb.CreateUserRequest,
) (*pb.UserProfile, error) {
	if req.GetEmail() == "" {
		return nil, mw.ValidationFailed("an email address is required")
	}
	role := req.GetRole()
	if !auth.ValidRole(role) {
		return nil, mw.ValidationFailed("an unknown role was requested")
	}

	candidate, err := newUserRecord(req.GetEmail(), req.GetPassword(), role)
	if err != nil {
		return nil, err
	}

	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	created, err := s.users.Create(ctx, candidate)
	switch {
	case errors.Is(err, chdata.ErrEmailTaken):
		return nil, mw.Conflict("a user with that address already exists")
	case err != nil:
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionUserCreate, TargetType: "user",
		TargetID: created.ID.String(), AfterValue: auditableUser(created),
		Result: audit.ResultSuccess,
	})

	// The password is deliberately NOT returned. The contract's UserProfile has no
	// field for it, and adding one would put a credential in a response that gets
	// logged by proxies and cached by clients. An admin who did not supply a password
	// resets it through the same flow a user does.
	return toUserProfile(created, tenant), nil
}

// newUserRecord prepares a user for creation, hashing the password and seeding MFA.
//
// A password may be supplied; one is generated when it is not. Generating is the
// better default — an admin who types a colleague's password knows it, and the
// platform then cannot tell the two of them apart in its own audit trail.
func newUserRecord(email, password, role string) (chdata.User, error) {
	if password == "" {
		generated, err := auth.GenerateFeedToken()
		if err != nil {
			return chdata.User{}, mw.Internal().WithCause(err)
		}
		password = generated
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return chdata.User{}, mw.Internal().WithCause(err)
	}

	secret, err := auth.GenerateMFASecret("siem", email)
	if err != nil {
		return chdata.User{}, mw.Internal().WithCause(err)
	}

	return chdata.User{
		Email: email, PasswordHash: hash, Role: role,
		Status: chdata.UserStatusActive, MFASecret: secret.Secret,
	}, nil
}

// UpdateUser changes a user's role or status.
func (s *AdminService) UpdateUser(
	ctx context.Context, req *pb.UpdateUserRequest,
) (*pb.UserProfile, error) {
	userID, err := parseUUID(req.GetUserId(), "user id")
	if err != nil {
		return nil, err
	}

	before, err := s.users.Get(ctx, userID)
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return nil, mw.NotFound("user")
		}
		return nil, mw.Internal().WithCause(err)
	}

	if req.Role != nil && !auth.ValidRole(req.GetRole()) {
		return nil, mw.ValidationFailed("an unknown role was requested")
	}

	updated, err := s.users.Update(ctx, userID, applyUserEdit(req))
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// A role change is the single most security-relevant edit an admin can make, so it
	// is recorded under its own action; an investigator filtering the trail should not
	// have to diff two JSON blobs to find one.
	action := audit.ActionUserCreate
	if before.Role != updated.Role {
		action = audit.ActionRoleChange
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: action, TargetType: "user", TargetID: userID.String(),
		BeforeValue: auditableUser(before), AfterValue: auditableUser(updated),
		Result: audit.ResultSuccess,
	})

	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return toUserProfile(updated, tenant), nil
}

// applyUserEdit builds the mutation an update applies. Only fields the request SET are
// changed; a PATCH that overwrote unset fields would disable a user on every rename.
func applyUserEdit(req *pb.UpdateUserRequest) func(chdata.User) chdata.User {
	return func(current chdata.User) chdata.User {
		if req.Role != nil {
			current.Role = req.GetRole()
		}
		if req.Status != nil {
			current.Status = req.GetStatus()
		}
		if req.GetResetMfa() {
			// Clearing the flag forces re-enrolment on the next login without
			// discarding the secret, so an operator can undo an accidental reset.
			current.MFAEnabled = false
		}
		return current
	}
}

// DeleteUser disables a user.
//
// Disabled rather than removed: the audit trail references the actor by id, and a
// deleted user turns every entry they produced into an unattributable one.
func (s *AdminService) DeleteUser(
	ctx context.Context, req *pb.DeleteUserRequest,
) (*pb.DeleteUserResponse, error) {
	userID, err := parseUUID(req.GetUserId(), "user id")
	if err != nil {
		return nil, err
	}

	disabled, err := s.users.Update(ctx, userID, func(current chdata.User) chdata.User {
		current.Status = chdata.UserStatusDisabled
		return current
	})
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return nil, mw.NotFound("user")
		}
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionUserDelete, TargetType: "user", TargetID: userID.String(),
		AfterValue: auditableUser(disabled), Result: audit.ResultSuccess,
	})

	return &pb.DeleteUserResponse{}, nil
}

// ---------------------------------------------------------------- tenant settings

// GetTenantSettings returns retention and redaction configuration.
func (s *AdminService) GetTenantSettings(
	ctx context.Context, _ *pb.GetTenantSettingsRequest,
) (*pb.TenantSettings, error) {
	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return toTenantSettings(tenant), nil
}

// UpdateTenantSettings changes retention and redaction.
func (s *AdminService) UpdateTenantSettings(
	ctx context.Context, req *pb.UpdateTenantSettingsRequest,
) (*pb.TenantSettings, error) {
	before, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// Validated and encoded BEFORE the update, so a malformed rule is refused outright
	// rather than stored. A rule that cannot compile filters nothing at runtime, which
	// looks identical to a rule that works — right up until someone compares the volume.
	encodedFilters, err := encodeIngestFilters(req.GetIngestFilters())
	if err != nil {
		return nil, err
	}

	updated, err := s.tenants.Update(ctx, func(current chdata.Tenant) chdata.Tenant {
		if req.RawRetentionDays != nil {
			current.RawRetentionDays = clampRetention(req.GetRawRetentionDays())
		}
		if req.CorrelatedRetentionDays != nil {
			current.CorrelatedRetentionDays = clampRetention(req.GetCorrelatedRetentionDays())
		}
		if req.AlertRetentionDays != nil {
			current.AlertRetentionDays = clampRetention(req.GetAlertRetentionDays())
		}
		if req.RedactedFields != nil {
			current.RedactedFields = req.GetRedactedFields()
		}
		if req.ScoreConflictThreshold != nil {
			current.ScoreConflictThreshold = req.GetScoreConflictThreshold()
		}
		if req.IngestFilters != nil {
			current.IngestFilters = encodedFilters
		}
		return current
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionRetentionChange, TargetType: "tenant",
		TargetID:    updated.ID.String(),
		BeforeValue: auditableTenant(before), AfterValue: auditableTenant(updated),
		Result: audit.ResultSuccess,
	})

	s.invalidate(updated.ID)
	return toTenantSettings(updated), nil
}

// GetCorrelationSettings returns the tenant's correlation tuning.
func (s *AdminService) GetCorrelationSettings(
	ctx context.Context, _ *pb.GetCorrelationSettingsRequest,
) (*pb.CorrelationSettings, error) {
	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return toCorrelationSettings(tenant), nil
}

// UpdateCorrelationSettings changes the correlation window and lateness bound.
func (s *AdminService) UpdateCorrelationSettings(
	ctx context.Context, req *pb.UpdateCorrelationSettingsRequest,
) (*pb.CorrelationSettings, error) {
	before, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	if err := validateCorrelationSettings(req); err != nil {
		return nil, err
	}

	updated, err := s.tenants.Update(ctx, func(current chdata.Tenant) chdata.Tenant {
		if req.CorrelationWindowMs != nil {
			current.CorrelationWindowMS = req.GetCorrelationWindowMs()
		}
		if req.LatenessBoundMs != nil {
			current.LatenessBoundMS = req.GetLatenessBoundMs()
		}
		return current
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionCorrelationSettingsChange, TargetType: "tenant",
		TargetID:    updated.ID.String(),
		BeforeValue: auditableTenant(before), AfterValue: auditableTenant(updated),
		Result: audit.ResultSuccess,
	})

	s.invalidate(updated.ID)
	return toCorrelationSettings(updated), nil
}

// validateCorrelationSettings rejects values the correlator would only clamp later.
//
// Rejecting here rather than clamping silently: an operator who asks for a one-hour
// window and gets five minutes without being told has been overruled invisibly.
func validateCorrelationSettings(req *pb.UpdateCorrelationSettingsRequest) error {
	if req.CorrelationWindowMs != nil {
		window := time.Duration(req.GetCorrelationWindowMs()) * time.Millisecond
		if window < correlate.MinWindow || window > correlate.MaxWindow {
			return mw.ValidationFailed(fmt.Sprintf(
				"the correlation window must be between %s and %s",
				correlate.MinWindow, correlate.MaxWindow))
		}
	}
	if req.LatenessBoundMs != nil {
		bound := time.Duration(req.GetLatenessBoundMs()) * time.Millisecond
		if bound < correlate.MinLatenessBound || bound > correlate.MaxLatenessBound {
			return mw.ValidationFailed(fmt.Sprintf(
				"the lateness bound must be between %s and %s",
				correlate.MinLatenessBound, correlate.MaxLatenessBound))
		}
	}
	return nil
}

func (s *AdminService) invalidate(tenantID uuid.UUID) {
	if s.invalidator != nil {
		s.invalidator.Invalidate(tenantID)
	}
}

// ---------------------------------------------------------------- purge

// Purge deletes a time range, audited (FR-036).
func (s *AdminService) Purge(
	ctx context.Context, req *pb.PurgeRequest,
) (*pb.PurgeResponse, error) {
	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// The confirmation must equal the tenant name. A destructive operation should not
	// be reachable by an accidental click, and typing the name is the cheapest control
	// that proves the operator knew which tenant they were in.
	if req.GetConfirmation() != tenant.Name {
		return nil, mw.ValidationFailed(
			"the confirmation must match the tenant name")
	}
	if req.GetReason() == "" {
		return nil, mw.ValidationFailed("a purge requires a stated reason")
	}

	r := req.GetRange()
	if r == nil || r.GetFrom() == nil || r.GetTo() == nil {
		return nil, mw.TimeRangeRequired()
	}

	actor := actorID(ctx)
	email := ""
	if claims, ok := auth.ClaimsFromContext(ctx); ok {
		email = claims.Email
	}

	err = s.purger.Purge(ctx, retention.PurgeRequest{
		TenantID:   tenant.ID,
		From:       r.GetFrom().AsTime(),
		To:         r.GetTo().AsTime(),
		Reason:     req.GetReason(),
		Actor:      &actor,
		ActorEmail: email,
	})
	if err != nil {
		return nil, mw.AsError(err)
	}

	// rows_deleted is not reported: ClickHouse applies a lightweight DELETE
	// asynchronously and does not return a count, so any number here would be invented.
	return &pb.PurgeResponse{}, nil
}

// ---------------------------------------------------------------- audit

// ListAuditEntries returns the audit trail.
func (s *AdminService) ListAuditEntries(
	ctx context.Context, req *pb.ListAuditEntriesRequest,
) (*pb.ListAuditEntriesResponse, error) {
	r := req.GetRange()
	if r == nil || r.GetFrom() == nil || r.GetTo() == nil {
		return nil, mw.TimeRangeRequired()
	}

	entries, err := s.auditLog.List(ctx, chdata.ListFilter{
		From:       r.GetFrom().AsTime(),
		To:         r.GetTo().AsTime(),
		Action:     req.GetAction(),
		ActorEmail: req.GetActorEmail(),
		Limit:      req.GetPage().GetLimit(),
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// The integrity indicator is verified over the UNFILTERED range, not over the rows
	// being returned. A filtered or paginated view is not a chain — its entries are not
	// adjacent — so checking the visible rows would report a break whenever an operator
	// narrowed by action or turned a page.
	// A broken chain is reported, not raised. It is a finding to be SHOWN rather than a
	// reason to withhold the trail — the entries are exactly what an investigator needs
	// at the moment integrity is in doubt.
	chainIntact := s.auditLog.VerifyChain(
		ctx, r.GetFrom().AsTime(), r.GetTo().AsTime()) == nil

	out := &pb.ListAuditEntriesResponse{
		Entries:     make([]*pb.AuditEntry, 0, len(entries)),
		ChainIntact: chainIntact,
	}
	for _, entry := range entries {
		out.Entries = append(out.Entries, toAuditEntryProto(entry))
	}
	return out, nil
}

// sourceIPString renders an address, leaving it empty when none was recorded rather
// than emitting the string "<nil>".
func sourceIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func toAuditEntryProto(e audit.Entry) *pb.AuditEntry {
	return &pb.AuditEntry{
		EntryId:     e.EntryID.String(),
		OccurredAt:  timestamppb.New(e.OccurredAt),
		ActorEmail:  e.ActorEmail,
		SourceIp:    sourceIPString(e.SourceIP),
		Action:      string(e.Action),
		TargetType:  e.TargetType,
		TargetId:    e.TargetID,
		BeforeValue: e.BeforeValue,
		AfterValue:  e.AfterValue,
		Result:      string(e.Result),
		Detail:      e.Detail,
		// The chain, so a reader can verify the linkage rather than take the
		// platform's word for its own integrity.
		EntryHash:    e.EntryHash,
		PreviousHash: e.PrevHash,
	}
}

// clampRetention bounds a configured window rather than trusting the input.
func clampRetention(days uint32) uint16 {
	switch {
	case days < retention.MinRetentionDays:
		return retention.MinRetentionDays
	case days > retention.MaxRetentionDays:
		return retention.MaxRetentionDays
	default:
		return uint16(days)
	}
}

func toTenantSettings(t chdata.Tenant) *pb.TenantSettings {
	return &pb.TenantSettings{
		TenantId:                t.ID.String(),
		Name:                    t.Name,
		RawRetentionDays:        uint32(t.RawRetentionDays),
		CorrelatedRetentionDays: uint32(t.CorrelatedRetentionDays),
		AlertRetentionDays:      uint32(t.AlertRetentionDays),
		RedactedFields:          t.RedactedFields,
		ScoreConflictThreshold:  t.ScoreConflictThreshold,
		IngestFilters:           toIngestFilterRules(t.IngestFilters),
	}
}

// encodeIngestFilters validates a rule set and renders it for storage.
//
// Compiling here is the validation: it is the same function the ingest path uses, so a
// rule that is accepted is a rule that will actually be applied.
func encodeIngestFilters(rules []*pb.IngestFilterRule) (string, error) {
	if len(rules) == 0 {
		return "[]", nil
	}

	converted := make([]filter.Rule, 0, len(rules))
	for _, rule := range rules {
		converted = append(converted, filter.Rule{
			Field: rule.GetField(), Op: rule.GetOp(), Values: rule.GetValues(),
		})
	}
	if _, err := filter.Compile(converted); err != nil {
		return "", mw.ValidationFailed(err.Error())
	}

	encoded, err := filter.Encode(converted)
	if err != nil {
		return "", mw.Internal().WithCause(err)
	}
	return encoded, nil
}

// toIngestFilterRules renders stored rules for the API.
//
// Undecodable content yields an empty list rather than an error: the settings page must
// still open so the operator can replace whatever is wrong, and the ingest path treats it
// as "no filters" for the same reason.
func toIngestFilterRules(encoded string) []*pb.IngestFilterRule {
	rules, err := filter.Decode(encoded)
	if err != nil {
		return nil
	}

	out := make([]*pb.IngestFilterRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, &pb.IngestFilterRule{
			Field: rule.Field, Op: rule.Op, Values: rule.Values,
		})
	}
	return out
}

func toCorrelationSettings(t chdata.Tenant) *pb.CorrelationSettings {
	return &pb.CorrelationSettings{
		CorrelationWindowMs: t.CorrelationWindowMS,
		LatenessBoundMs:     t.LatenessBoundMS,
	}
}

// auditableUser renders a user for the trail WITHOUT their password hash or MFA secret.
func auditableUser(u chdata.User) string {
	encoded, err := json.Marshal(map[string]any{
		"email": u.Email, "role": u.Role, "status": u.Status,
		"mfa_enabled": u.MFAEnabled,
	})
	if err != nil {
		return `{"email":"(unrenderable)"}`
	}
	return string(encoded)
}

// auditableTenant renders tenant settings for the trail.
func auditableTenant(t chdata.Tenant) string {
	encoded, err := json.Marshal(map[string]any{
		"raw_retention_days":        t.RawRetentionDays,
		"correlated_retention_days": t.CorrelatedRetentionDays,
		"alert_retention_days":      t.AlertRetentionDays,
		"redacted_fields":           t.RedactedFields,
		"correlation_window_ms":     t.CorrelationWindowMS,
		"lateness_bound_ms":         t.LatenessBoundMS,
		"score_conflict_threshold":  t.ScoreConflictThreshold,
	})
	if err != nil {
		return `{}`
	}
	return string(encoded)
}
