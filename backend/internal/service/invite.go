package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
	"github.com/menta2k/siem/internal/auth"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
)

// invalidSetupToken is the ONE answer every failed redemption gets.
//
// Malformed, unknown, wrong secret, already spent, expired, disabled account, suspended
// tenant — all of them return this. Distinguishing them would turn the public endpoint
// into an oracle: "already redeemed" confirms an account exists and has been set up,
// and "expired" confirms a token was once real. The admin who issued the invite is the
// one who can tell the user which it was, and they can see it in the audit trail.
//
// VALIDATION_FAILED rather than UNAUTHENTICATED on purpose: the SPA treats a 401 as
// "your session died, go to /login", which is exactly the wrong thing to do to someone
// standing on the setup page who has no session to begin with.
func invalidSetupToken() *mw.Error {
	return mw.ValidationFailed("this setup link is not valid, or has already been used")
}

// ---------------------------------------------------------------- issuing

// IssueUserInvite mints a one-time setup token for a user.
//
// Re-issuable by design. The token is unrecoverable once the response is gone — only
// its hash is stored — so "the invite never arrived" has to be answerable by minting a
// fresh one, and doing so invalidates its predecessor.
//
// It is accepted for an ACTIVE user too, where it acts as an admin-driven password
// reset. Their status is deliberately left alone: demoting an active colleague to
// `invited` because someone clicked resend would lock them out of an account that was
// working. What it does NOT do in either case is touch MFA — a reset link gets the
// holder as far as a password, and the second factor still stands behind it.
func (s *AdminService) IssueUserInvite(
	ctx context.Context, req *pb.IssueUserInviteRequest,
) (*pb.UserInvite, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	user, err := s.invitableUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}

	token, err := auth.NewInviteToken(tenantID, user.ID)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	expiresAt := s.now().UTC().Add(auth.DefaultInviteTTL)
	issued, err := s.invites.Issue(ctx, chdata.Invite{
		UserID:    user.ID,
		TokenHash: token.SecretHash(),
		Email:     user.Email,
		IssuedBy:  actorUserID(ctx),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	recordAudit(ctx, s.auditLog, audit.Record{
		Action: audit.ActionUserInvite, TargetType: "user", TargetID: user.ID.String(),
		AfterValue: auditableInvite(issued), Result: audit.ResultSuccess,
	})

	return &pb.UserInvite{
		UserId:     user.ID.String(),
		Email:      user.Email,
		SetupToken: token.Encode(),
		ExpiresAt:  timestamppb.New(issued.ExpiresAt),
	}, nil
}

// invitableUser loads the subject of an invite and refuses the states that must not
// receive one.
func (s *AdminService) invitableUser(
	ctx context.Context, rawID string,
) (chdata.User, error) {
	userID, err := parseUUID(rawID, "user id")
	if err != nil {
		return chdata.User{}, err
	}

	user, err := s.users.Get(ctx, userID)
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return chdata.User{}, mw.NotFound("user")
		}
		return chdata.User{}, mw.Internal().WithCause(err)
	}
	// A disabled account is disabled. Handing out a setup token for one would let it be
	// walked back into service by whoever holds the link, rather than by an admin.
	if user.Status == chdata.UserStatusDisabled {
		return chdata.User{}, mw.ValidationFailed("re-enable the account before inviting it")
	}
	return user, nil
}

// ---------------------------------------------------------------- redeeming

// PreviewInvite names the account a setup token belongs to, without spending it.
func (s *AuthService) PreviewInvite(
	ctx context.Context, req *pb.PreviewInviteRequest,
) (*pb.PreviewInviteResponse, error) {
	if req.GetSetupToken() == "" {
		return nil, mw.ValidationFailed("a setup token is required")
	}

	_, invite, _, err := s.resolveInvite(ctx, req.GetSetupToken())
	if err != nil {
		return nil, err
	}

	return &pb.PreviewInviteResponse{
		Email:     invite.Email,
		ExpiresAt: timestamppb.New(invite.ExpiresAt),
	}, nil
}

// RedeemInvite spends a setup token: it sets the account's first password and, for an
// account that has never had one, activates it.
//
// No token pair is returned. Redemption proves possession of the setup link and nothing
// more, and MFA is not enrolled at this point — issuing a session here would be a way
// into the platform that never passes a second factor. The user signs in afterwards and
// enrols through the normal first-login path.
func (s *AuthService) RedeemInvite(
	ctx context.Context, req *pb.RedeemInviteRequest,
) (*pb.RedeemInviteResponse, error) {
	if req.GetSetupToken() == "" || req.GetPassword() == "" {
		return nil, mw.ValidationFailed("a setup token and a password are required")
	}
	// Checked BEFORE the token is looked at, let alone spent. A password the policy
	// rejects must not cost the user their one-time link.
	if err := auth.ValidatePassword(req.GetPassword()); err != nil {
		return nil, mw.ValidationFailed(err.Error())
	}

	scoped, invite, user, err := s.resolveInvite(ctx, req.GetSetupToken())
	if err != nil {
		return nil, err
	}

	// Hashing is deliberately done before the invite is consumed: argon2id can fail on a
	// memory-starved host, and burning the token for a password that was never stored
	// would strand the user.
	hash, err := auth.HashPassword(req.GetPassword())
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	// Consume FIRST, then write the password. The two writes cannot be one transaction —
	// ClickHouse has none — so the order picks which way a crash between them fails. This
	// way the user re-requests an invite; the other way a live token could reset the same
	// password again and again.
	if _, err := s.invites.MarkRedeemed(scoped, invite.TenantID, invite.UserID, s.now()); err != nil {
		if errors.Is(err, chdata.ErrInviteSpent) || errors.Is(err, chdata.ErrNotFound) {
			s.recordInviteDenied(scoped, invite, "the invite was already redeemed")
			return nil, invalidSetupToken()
		}
		return nil, mw.Internal().WithCause(err)
	}

	updated, err := s.users.Update(scoped, user.ID, func(u chdata.User) chdata.User {
		u.PasswordHash = hash
		// Only an account that was awaiting setup is activated. Redeeming a reset link
		// for an already-active user must not resurrect one an admin has disabled since.
		if u.AwaitingSetup() {
			u.Status = chdata.UserStatusActive
		}
		return u
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	s.record(scoped, audit.Record{
		ActorUserID: &updated.ID, ActorEmail: updated.Email, SourceIP: sourceIP(ctx),
		Action: audit.ActionUserInviteRedeem, TargetType: "user",
		TargetID: updated.ID.String(), AfterValue: auditableUser(updated),
		Result: audit.ResultSuccess,
	})

	return &pb.RedeemInviteResponse{Email: updated.Email}, nil
}

// resolveInvite validates a presented token and loads what it names.
//
// Shared by preview and redemption so the two cannot drift apart on which tokens they
// accept — a preview that says "valid" for something redemption then rejects is a bug
// report from every new joiner.
func (s *AuthService) resolveInvite(
	ctx context.Context, encoded string,
) (context.Context, chdata.Invite, chdata.User, error) {
	token, err := auth.ParseInviteToken(encoded)
	if err != nil {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}

	invite, err := s.invites.Find(ctx, token.TenantID, token.UserID)
	if err != nil {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}
	// The token names its own tenant and user, so those are attacker-chosen. The secret
	// is not: this comparison is the whole of the authentication.
	if !token.MatchesHash(invite.TokenHash) {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}
	if !invite.Redeemable(s.now()) {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: invite.TenantID})

	user, err := s.users.Get(scoped, invite.UserID)
	if err != nil {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}
	if user.Status == chdata.UserStatusDisabled {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}

	// A suspended tenant's invites do not resolve. Letting one through would create a
	// working account inside a tenant that is not permitted to operate.
	tenant, err := s.tenants.GetByID(scoped, invite.TenantID)
	if err != nil {
		return nil, chdata.Invite{}, chdata.User{}, mw.Internal().WithCause(err)
	}
	if !tenant.Active() {
		return nil, chdata.Invite{}, chdata.User{}, invalidSetupToken()
	}

	return scoped, invite, user, nil
}

// recordInviteDenied notes a refused redemption. A replayed token is exactly the kind
// of thing an investigator wants to find in the trail.
func (s *AuthService) recordInviteDenied(
	ctx context.Context, invite chdata.Invite, reason string,
) {
	s.record(ctx, audit.Record{
		ActorEmail: invite.Email, SourceIP: sourceIP(ctx),
		Action: audit.ActionUserInviteRedeem, TargetType: "user",
		TargetID: invite.UserID.String(), Result: audit.ResultDenied, Detail: reason,
	})
}

// auditableInvite renders an issuance for the trail. The token is not in it, and must
// never be: the audit table is the one place in the system designed never to forget.
func auditableInvite(i chdata.Invite) string {
	encoded, err := json.Marshal(map[string]any{
		"email":      i.Email,
		"expires_at": i.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return `{"email":"(unrenderable)"}`
	}
	return string(encoded)
}

// actorUserID reads the authenticated admin's id, for the invite's issued_by column.
// Nil when there is no authenticated caller, which is the seed path rather than a
// request.
func actorUserID(ctx context.Context) *uuid.UUID {
	id, err := userIDFromContext(ctx)
	if err != nil {
		return nil
	}
	return &id
}
