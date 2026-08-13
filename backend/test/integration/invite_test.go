//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/auth"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/test/support"
)

// inviteServices builds the two services the flow spans, over the real repositories.
//
// Deliberately not mocked. The properties under test — one live invite per user, a
// token that is spent exactly once, an account that cannot authenticate until it is
// redeemed — are properties of the ReplacingMergeTree row layout and the Redis lock,
// and a fake repository would assert only that the test author agreed with themselves.
func inviteServices(
	t *testing.T, f *support.Fixture,
) (*service.AdminService, *service.AuthService) {
	t.Helper()

	tokens, err := auth.NewTokenIssuer(
		strings.Repeat("k", 32), time.Minute, time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}

	admin := service.NewAdminService(f.Users, f.Tenants, f.Audit, f.Invites, nil, nil,
		secrets.NewMemoryStore(), "", mw.NewLogger("error", "json"))
	authSvc := service.NewAuthService(f.Users, f.Tenants, f.Audit, f.Invites, tokens,
		f.Users, "siem")

	return admin, authSvc
}

// invitedUser creates an account through the ordinary admin path and returns it.
func invitedUser(
	t *testing.T, admin *service.AdminService, ctx context.Context, email string,
) *pb.UserProfile {
	t.Helper()

	profile, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: email, Role: auth.RoleAnalyst,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return profile
}

// The happy path, end to end: an admin creates an account, issues a setup token, and
// the new joiner turns it into a password they alone know.
func TestInviteRedemptionActivatesTheAccount(t *testing.T) {
	f, ctx := support.SharedTenant(t, "inviteflow")
	admin, authSvc := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "joiner@example.com")

	// The account exists but cannot be signed into: no password was ever chosen for it.
	before := userByID(t, f, ctx, profile.GetUserId())
	if before.Status != chdata.UserStatusInvited {
		t.Fatalf("new user status = %q, want %q", before.Status, chdata.UserStatusInvited)
	}
	if before.Active() {
		t.Fatal("a user awaiting setup reports itself active, so login would accept it")
	}

	invite, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}
	if invite.GetSetupToken() == "" {
		t.Fatal("no setup token was returned; the invite is unusable")
	}

	// Preview names the account without spending the token.
	preview, err := authSvc.PreviewInvite(context.Background(),
		&pb.PreviewInviteRequest{SetupToken: invite.GetSetupToken()})
	if err != nil {
		t.Fatalf("PreviewInvite() error = %v", err)
	}
	if preview.GetEmail() != "joiner@example.com" {
		t.Errorf("preview email = %q, want joiner@example.com", preview.GetEmail())
	}

	const chosen = "a passphrase they picked"
	redeemed, err := authSvc.RedeemInvite(context.Background(),
		&pb.RedeemInviteRequest{SetupToken: invite.GetSetupToken(), Password: chosen})
	if err != nil {
		t.Fatalf("RedeemInvite() error = %v", err)
	}
	if redeemed.GetEmail() != "joiner@example.com" {
		t.Errorf("redeemed email = %q, want joiner@example.com", redeemed.GetEmail())
	}

	after := userByID(t, f, ctx, profile.GetUserId())
	if !after.Active() {
		t.Errorf("status after redemption = %q, want %q", after.Status, chdata.UserStatusActive)
	}
	if err := auth.VerifyPassword(chosen, after.PasswordHash); err != nil {
		t.Errorf("the chosen password does not verify against the stored hash: %v", err)
	}
	// MFA is deliberately untouched, so the first sign-in still runs enrolment. A
	// redemption that pre-enrolled would hand out an account with no second factor.
	if after.MFAEnabled {
		t.Error("redemption enrolled MFA; the first login would skip the enrolment step")
	}
}

// THE PROPERTY THE WHOLE DESIGN EXISTS FOR. A setup token is spent exactly once. If a
// replay succeeded, a link sitting in a forwarded email or a chat scrollback would stay
// a permanent password-reset capability for that account.
func TestASetupTokenCannotBeRedeemedTwice(t *testing.T) {
	f, ctx := support.SharedTenant(t, "invitereplay")
	admin, authSvc := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "replay@example.com")
	invite, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "the first password",
	}); err != nil {
		t.Fatalf("first RedeemInvite() error = %v", err)
	}

	_, err = authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "an attacker's password",
	})
	if err == nil {
		t.Fatal("the same setup token was redeemed twice")
	}

	// And the first password still stands — the replay changed nothing.
	after := userByID(t, f, ctx, profile.GetUserId())
	if err := auth.VerifyPassword("the first password", after.PasswordHash); err != nil {
		t.Error("the replayed redemption overwrote the password it should not have touched")
	}
}

// Re-issuing is how "resend the invite" works, and it must kill the previous token.
// Two live setup links for one account would mean a leaked-and-superseded link stays
// dangerous forever.
func TestReissuingAnInviteInvalidatesThePreviousToken(t *testing.T) {
	f, ctx := support.SharedTenant(t, "invitereissue")
	admin, authSvc := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "resend@example.com")

	first, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("first IssueUserInvite() error = %v", err)
	}
	second, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("second IssueUserInvite() error = %v", err)
	}
	if first.GetSetupToken() == second.GetSetupToken() {
		t.Fatal("re-issuing returned the same token, so nothing was rotated")
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: first.GetSetupToken(), Password: "using the superseded link",
	}); err == nil {
		t.Fatal("the superseded setup token still worked")
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: second.GetSetupToken(), Password: "using the current link",
	}); err != nil {
		t.Fatalf("the current setup token was rejected: %v", err)
	}
}

// A token whose keys name a real account but whose secret is someone else's must fail.
// The keys travel in the clear, so this is the case an attacker actually has: they can
// name any user they like.
func TestAForgedTokenForARealAccountIsRejected(t *testing.T) {
	f, ctx := support.SharedTenant(t, "inviteforge")
	admin, authSvc := inviteServices(t, f)

	victim := invitedUser(t, admin, ctx, "victim@example.com")
	issued, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: victim.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}

	// Same keys, a secret of the attacker's own choosing.
	keys, _, _ := strings.Cut(issued.GetSetupToken(), ".")
	forged := keys + ".8ryFSGX2eXm0oLh5H0Zg5vUj4hFJmYVJgHVBDGa1nBw"

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: forged, Password: "an attacker's password",
	}); err == nil {
		t.Fatal("a forged token was accepted for a real account")
	}

	// The real token still works, so the failed attempt did not consume it either.
	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: issued.GetSetupToken(), Password: "the real user's passphrase",
	}); err != nil {
		t.Fatalf("a forgery attempt burned the legitimate token: %v", err)
	}
}

// A password the policy rejects must not cost the user their one-time link. Getting
// this backwards means every user who first tries a short password is locked out and
// has to ask an admin for a new invite.
func TestAWeakPasswordDoesNotConsumeTheInvite(t *testing.T) {
	f, ctx := support.SharedTenant(t, "inviteweak")
	admin, authSvc := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "weak@example.com")
	invite, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "short",
	}); err == nil {
		t.Fatal("a password below the length floor was accepted")
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "a long enough passphrase",
	}); err != nil {
		t.Fatalf("the invite was consumed by the rejected attempt: %v", err)
	}
}

// An expired invite is not redeemable. The row is written directly because the service
// has no way to issue a token in the past, and waiting out the real TTL is a week.
func TestAnExpiredInviteIsRejected(t *testing.T) {
	f, ctx := support.SharedTenant(t, "inviteexpiry")
	admin, authSvc := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "expired@example.com")
	invite, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}

	token, err := auth.ParseInviteToken(invite.GetSetupToken())
	if err != nil {
		t.Fatalf("ParseInviteToken() error = %v", err)
	}
	if _, err := f.Invites.Issue(ctx, chdata.Invite{
		UserID:    token.UserID,
		TokenHash: token.SecretHash(),
		Email:     "expired@example.com",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "a long enough passphrase",
	}); err == nil {
		t.Fatal("an expired setup token was accepted")
	}
}

// A disabled account must not be walked back into service by whoever holds an old
// setup link. Re-enabling it is an admin's decision.
func TestADisabledAccountCannotBeInvitedOrRedeemed(t *testing.T) {
	f, ctx := support.SharedTenant(t, "invitedisabled")
	admin, authSvc := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "disabled@example.com")
	invite, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}

	if _, err := admin.DeleteUser(ctx,
		&pb.DeleteUserRequest{UserId: profile.GetUserId()}); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "a long enough passphrase",
	}); err == nil {
		t.Fatal("a disabled account was activated by redeeming an old setup link")
	}

	if _, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()}); err == nil {
		t.Fatal("a setup token was issued for a disabled account")
	}
}

// Redeeming a link for an ALREADY-ACTIVE user is the admin-driven password reset. It
// sets the new password and must leave the account's status exactly where it was.
func TestRedeemingForAnActiveUserResetsThePasswordOnly(t *testing.T) {
	f, ctx := support.SharedTenant(t, "invitereset")
	admin, authSvc := inviteServices(t, f)

	profile, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "active@example.com", Role: auth.RoleAnalyst,
		Password: "the original password",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if got := userByID(t, f, ctx, profile.GetUserId()); !got.Active() {
		t.Fatalf("a user created WITH a password has status %q, want active", got.Status)
	}

	invite, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()})
	if err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}
	// Issuing must not lock a working account out; that would make "resend invite" a
	// destructive button.
	if got := userByID(t, f, ctx, profile.GetUserId()); !got.Active() {
		t.Errorf("issuing an invite demoted an active user to %q", got.Status)
	}

	if _, err := authSvc.RedeemInvite(context.Background(), &pb.RedeemInviteRequest{
		SetupToken: invite.GetSetupToken(), Password: "the replacement password",
	}); err != nil {
		t.Fatalf("RedeemInvite() error = %v", err)
	}

	after := userByID(t, f, ctx, profile.GetUserId())
	if err := auth.VerifyPassword("the replacement password", after.PasswordHash); err != nil {
		t.Errorf("the replacement password does not verify: %v", err)
	}
	if err := auth.VerifyPassword("the original password", after.PasswordHash); err == nil {
		t.Error("the original password still works after a reset")
	}
}

// userByID reads a user straight from the repository, bypassing the profile projection
// so a test can assert on status and password hash.
func userByID(
	t *testing.T, f *support.Fixture, ctx context.Context, id string,
) chdata.User {
	t.Helper()

	parsed, err := uuid.Parse(id)
	if err != nil {
		t.Fatalf("user id %q is not a uuid: %v", id, err)
	}
	user, err := f.Users.Get(ctx, parsed)
	if err != nil {
		t.Fatalf("Users.Get(%s) error = %v", id, err)
	}
	return user
}
