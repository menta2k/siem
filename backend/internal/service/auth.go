// Package service implements the proto-defined services.
//
// Services orchestrate: they validate input at the boundary, call the domain and
// data layers, and write audit entries. They hold no storage logic and no
// authorization decisions — authorization already happened in middleware before a
// handler runs.
package service

import (
	"context"
	"net"
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

// TenantResolver maps a login email to the tenant that owns it.
type TenantResolver interface {
	ResolveByEmail(ctx context.Context, email string) (uuid.UUID, error)
}

// AuthService implements the Auth proto service.
type AuthService struct {
	users     *chdata.UserRepo
	tenants   *chdata.TenantRepo
	auditLog  *chdata.AuditRepo
	tokens    *auth.TokenIssuer
	resolver  TenantResolver
	mfaIssuer string
	now       func() time.Time
}

// NewAuthService constructs the service.
func NewAuthService(
	users *chdata.UserRepo,
	tenants *chdata.TenantRepo,
	auditLog *chdata.AuditRepo,
	tokens *auth.TokenIssuer,
	resolver TenantResolver,
	mfaIssuer string,
) *AuthService {
	return &AuthService{
		users:     users,
		tenants:   tenants,
		auditLog:  auditLog,
		tokens:    tokens,
		resolver:  resolver,
		mfaIssuer: mfaIssuer,
		now:       time.Now,
	}
}

// Login verifies the password and returns an MFA challenge — never an access token.
//
// Every failure path returns the same error and takes a comparable amount of work, so
// the endpoint cannot be used to enumerate valid addresses.
func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.GetEmail() == "" || req.GetPassword() == "" {
		return nil, mw.ValidationFailed("email and password are required")
	}

	tenantID, user, err := s.lookup(ctx, req.GetEmail())
	if err != nil {
		// The address is unknown. A password hash is still verified against a dummy
		// value so the response time does not distinguish this case.
		auth.VerifyDummyPassword()
		return nil, mw.Unauthenticated("invalid email or password")
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenantID})

	if err := auth.VerifyPassword(req.GetPassword(), user.PasswordHash); err != nil {
		s.recordLoginFailure(scoped, req.GetEmail(), "invalid password")
		return nil, mw.Unauthenticated("invalid email or password")
	}
	if !user.Active() {
		s.recordLoginFailure(scoped, req.GetEmail(), "account disabled")
		return nil, mw.Unauthenticated("invalid email or password")
	}

	identity := auth.Identity{
		UserID: user.ID, Email: user.Email, TenantID: tenantID, Role: user.Role,
	}
	challenge, err := s.tokens.IssueMFAChallenge(identity)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	resp := &pb.LoginResponse{MfaChallengeToken: challenge}

	// First login: enrol MFA now rather than allowing an account to exist without it.
	if !user.MFAEnabled {
		secret, err := auth.GenerateMFASecret(s.mfaIssuer, user.Email)
		if err != nil {
			return nil, mw.Internal().WithCause(err)
		}
		if _, err := s.users.Update(scoped, user.ID, func(u chdata.User) chdata.User {
			u.MFASecret = secret.Secret
			return u
		}); err != nil {
			return nil, mw.Internal().WithCause(err)
		}
		resp.MfaEnrolmentRequired = true
		// Returned exactly once, during enrolment, and never again.
		resp.MfaProvisioningUri = secret.URI
	}

	return resp, nil
}

// VerifyMFA completes authentication and issues the token pair.
func (s *AuthService) VerifyMFA(
	ctx context.Context, req *pb.VerifyMFARequest,
) (*pb.TokenResponse, error) {
	if req.GetMfaChallengeToken() == "" || req.GetCode() == "" {
		return nil, mw.ValidationFailed("the challenge token and code are required")
	}

	scoped, user, tenant, err := s.resolveChallenge(ctx, req.GetMfaChallengeToken())
	if err != nil {
		return nil, err
	}

	if err := auth.VerifyMFACode(user.MFASecret, req.GetCode(), s.now()); err != nil {
		s.recordLoginFailure(scoped, user.Email, "invalid MFA code")
		return nil, mw.Unauthenticated("invalid code")
	}

	// Enrolment completes only after a code has actually been verified, so a half
	// enrolment cannot lock a user out or leave MFA effectively disabled.
	if !user.MFAEnabled {
		if _, err := s.users.Update(scoped, user.ID, func(u chdata.User) chdata.User {
			u.MFAEnabled = true
			return u
		}); err != nil {
			return nil, mw.Internal().WithCause(err)
		}
	}

	return s.completeLogin(scoped, user, tenant)
}

// resolveChallenge validates an MFA challenge token and loads the subject it names.
func (s *AuthService) resolveChallenge(
	ctx context.Context, challengeToken string,
) (context.Context, chdata.User, chdata.Tenant, error) {
	claims, err := s.tokens.ParseMFAChallenge(challengeToken)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("the challenge has expired; sign in again").WithCause(err)
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("malformed challenge").WithCause(err)
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("malformed challenge").WithCause(err)
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenantID})

	user, err := s.users.Get(scoped, userID)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("invalid challenge").WithCause(err)
	}
	tenant, err := s.tenants.GetByID(scoped, tenantID)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{}, mw.Internal().WithCause(err)
	}
	if !tenant.Active() {
		return nil, chdata.User{}, chdata.Tenant{}, mw.TenantSuspended()
	}
	return scoped, user, tenant, nil
}

// completeLogin issues tokens, stamps the login, and records the audit entry.
func (s *AuthService) completeLogin(
	ctx context.Context, user chdata.User, tenant chdata.Tenant,
) (*pb.TokenResponse, error) {
	pair, err := s.tokens.IssuePair(auth.Identity{
		UserID: user.ID, Email: user.Email,
		TenantID: tenant.ID, TenantName: tenant.Name, Role: user.Role,
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	loginAt := s.now().UTC()
	if err := s.users.RecordLogin(ctx, user.ID, loginAt); err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	s.record(ctx, audit.Record{
		ActorUserID: &user.ID, ActorEmail: user.Email, SourceIP: sourceIP(ctx),
		Action: audit.ActionLogin, TargetType: "user", TargetID: user.ID.String(),
		Result: audit.ResultSuccess,
	})

	user.LastLoginAt = &loginAt
	return &pb.TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    timestamppb.New(pair.ExpiresAt),
		User:         toUserProfile(user, tenant),
	}, nil
}

// Refresh rotates the token pair. The presented refresh token is revoked, so a stolen
// token becomes useless as soon as the legitimate holder refreshes.
func (s *AuthService) Refresh(
	ctx context.Context, req *pb.RefreshRequest,
) (*pb.TokenResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, mw.ValidationFailed("a refresh token is required")
	}

	claims, err := s.tokens.ParseRefresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, mw.Unauthenticated("the session has expired; sign in again").WithCause(err)
	}

	_, user, tenant, err := s.subjectOf(ctx, claims)
	if err != nil {
		return nil, err
	}

	// Revoke before reissuing: if issuing then fails, the old token is already dead
	// and the user re-authenticates. The reverse order would leave two live tokens.
	if err := s.tokens.Revoke(ctx, req.GetRefreshToken()); err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	pair, err := s.tokens.IssuePair(auth.Identity{
		UserID: user.ID, Email: user.Email,
		TenantID: tenant.ID, TenantName: tenant.Name, Role: user.Role,
	})
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}

	return &pb.TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    timestamppb.New(pair.ExpiresAt),
		User:         toUserProfile(user, tenant),
	}, nil
}

// subjectOf resolves the user and tenant a set of verified claims names, rejecting
// accounts and tenants that are no longer permitted to operate.
func (s *AuthService) subjectOf(
	ctx context.Context, claims *auth.Claims,
) (context.Context, chdata.User, chdata.Tenant, error) {
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("malformed token").WithCause(err)
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("malformed token").WithCause(err)
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenantID})

	user, err := s.users.Get(scoped, userID)
	if err != nil || !user.Active() {
		// A disabled account must not be able to extend its session.
		return nil, chdata.User{}, chdata.Tenant{},
			mw.Unauthenticated("the session is no longer valid")
	}
	tenant, err := s.tenants.GetByID(scoped, tenantID)
	if err != nil {
		return nil, chdata.User{}, chdata.Tenant{}, mw.Internal().WithCause(err)
	}
	if !tenant.Active() {
		return nil, chdata.User{}, chdata.Tenant{}, mw.TenantSuspended()
	}
	return scoped, user, tenant, nil
}

// Logout revokes the refresh token.
func (s *AuthService) Logout(
	ctx context.Context, req *pb.LogoutRequest,
) (*pb.LogoutResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, mw.ValidationFailed("a refresh token is required")
	}
	if err := s.tokens.Revoke(ctx, req.GetRefreshToken()); err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	return &pb.LogoutResponse{}, nil
}

// Me returns the authenticated user's profile.
func (s *AuthService) Me(ctx context.Context, _ *pb.MeRequest) (*pb.MeResponse, error) {
	tenant, err := s.tenants.Get(ctx)
	if err != nil {
		return nil, mw.Internal().WithCause(err)
	}
	userID, err := userIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, mw.NotFound("user").WithCause(err)
	}
	return &pb.MeResponse{User: toUserProfile(user, tenant)}, nil
}

// lookup resolves the tenant and user for a login address.
func (s *AuthService) lookup(ctx context.Context, email string) (uuid.UUID, chdata.User, error) {
	tenantID, err := s.resolver.ResolveByEmail(ctx, email)
	if err != nil {
		return uuid.Nil, chdata.User{}, err
	}
	user, err := s.users.FindByEmail(ctx, tenantID, email)
	if err != nil {
		return uuid.Nil, chdata.User{}, err
	}
	return tenantID, user, nil
}

func (s *AuthService) recordLoginFailure(ctx context.Context, email, reason string) {
	s.record(ctx, audit.Record{
		ActorEmail: email, SourceIP: sourceIP(ctx),
		Action: audit.ActionLoginFailed, TargetType: "user", TargetID: email,
		Result: audit.ResultDenied, Detail: reason,
	})
}

// record writes an audit entry. A failure to audit is logged but does not fail the
// request that was already authorized — losing the action AND the record is worse
// than losing only the record.
func (s *AuthService) record(ctx context.Context, r audit.Record) {
	if _, err := s.auditLog.Append(ctx, r); err != nil {
		// Surfaced through the AuditWriteFailed metric and alert rather than swallowed.
		auditWriteFailures.Inc()
	}
}

func toUserProfile(u chdata.User, t chdata.Tenant) *pb.UserProfile {
	p := &pb.UserProfile{
		UserId:     u.ID.String(),
		Email:      u.Email,
		Role:       u.Role,
		TenantId:   t.ID.String(),
		TenantName: t.Name,
		MfaEnabled: u.MFAEnabled,
	}
	if u.LastLoginAt != nil {
		p.LastLoginAt = timestamppb.New(*u.LastLoginAt)
	}
	return p
}

// userIDFromContext reads the authenticated user id placed by the auth middleware.
func userIDFromContext(ctx context.Context) (uuid.UUID, error) {
	claims, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		return uuid.Nil, mw.Unauthenticated("no authenticated user in context")
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, mw.Unauthenticated("malformed subject claim").WithCause(err)
	}
	return id, nil
}

// sourceIP extracts the caller address for the audit record.
func sourceIP(ctx context.Context) net.IP {
	if ip, ok := mw.SourceIPFromContext(ctx); ok {
		return ip
	}
	return nil
}

// Compile-time assertion that the service satisfies the generated contract. If a
// proto method is added or its signature changes, this fails the build rather than
// producing a route that 404s at runtime.
var _ pb.AuthHTTPServer = (*AuthService)(nil)
