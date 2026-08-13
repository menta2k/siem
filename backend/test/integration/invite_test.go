//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
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

// actingAs returns a context carrying an authenticated admin, the way the auth
// middleware would in a real request.
//
// Needed because recordAudit takes the actor from the claims on the context, and an
// audit.Record with neither an actor id nor an actor email fails Validate() and is
// dropped. A test that skips this sees every audited action silently write nothing —
// which is exactly what made the erasure test below assert against an empty trail.
func actingAs(ctx context.Context, actor *pb.UserProfile) context.Context {
	return auth.WithClaims(ctx, &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: actor.GetUserId()},
		Email:            actor.GetEmail(),
	})
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

// ---------------------------------------------------------------- erasure

// The happy path. Erasure removes the row, and the address becomes reusable — which is
// the difference an admin is actually asking for when they say "delete", and what
// disabling deliberately does not give them.
func TestErasingAUserRemovesTheRowAndFreesTheAddress(t *testing.T) {
	f, ctx := support.SharedTenant(t, "eraseuser")
	admin, _ := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "leaver@example.com")
	if _, err := admin.IssueUserInvite(ctx,
		&pb.IssueUserInviteRequest{UserId: profile.GetUserId()}); err != nil {
		t.Fatalf("IssueUserInvite() error = %v", err)
	}

	if _, err := admin.EraseUser(ctx, &pb.EraseUserRequest{
		UserId: profile.GetUserId(), ConfirmEmail: "leaver@example.com",
	}); err != nil {
		t.Fatalf("EraseUser() error = %v", err)
	}

	id, err := uuid.Parse(profile.GetUserId())
	if err != nil {
		t.Fatalf("parse user id: %v", err)
	}
	if _, err := f.Users.Get(ctx, id); !errors.Is(err, chdata.ErrNotFound) {
		t.Errorf("Users.Get after erase = %v, want ErrNotFound", err)
	}
	// The outstanding invite goes with them; a token pointing at a deleted user is a row
	// nothing can ever redeem.
	if _, err := f.Invites.Find(ctx, id, id); err == nil {
		t.Error("the erased user's invite row survived")
	}

	// The address is free again, which disabling never allows.
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "leaver@example.com", Role: auth.RoleAnalyst,
	}); err != nil {
		t.Errorf("re-creating the erased address failed: %v", err)
	}
}

// The confirmation is the caller stating which human they mean, because the id in the
// path is opaque. A mismatch is a wrong row, not a wrong keystroke.
func TestErasingRefusesAMismatchedConfirmation(t *testing.T) {
	f, ctx := support.SharedTenant(t, "erasemismatch")
	admin, _ := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "keepme@example.com")

	if _, err := admin.EraseUser(ctx, &pb.EraseUserRequest{
		UserId: profile.GetUserId(), ConfirmEmail: "someone.else@example.com",
	}); err == nil {
		t.Fatal("a mismatched confirmation address was accepted")
	}

	id, err := uuid.Parse(profile.GetUserId())
	if err != nil {
		t.Fatalf("parse user id: %v", err)
	}
	if _, err := f.Users.Get(ctx, id); err != nil {
		t.Errorf("the refused erase removed the user anyway: %v", err)
	}
}

// Capitalisation must not refuse a correctly-identified account: an admin who is taught
// the dialog rejects correct input stops reading it.
func TestErasingAcceptsADifferentlyCasedConfirmation(t *testing.T) {
	f, ctx := support.SharedTenant(t, "erasecase")
	admin, _ := inviteServices(t, f)

	profile := invitedUser(t, admin, ctx, "casing@example.com")

	if _, err := admin.EraseUser(ctx, &pb.EraseUserRequest{
		UserId: profile.GetUserId(), ConfirmEmail: "  Casing@Example.COM ",
	}); err != nil {
		t.Fatalf("EraseUser() rejected a correct address over casing: %v", err)
	}
}

// A tenant whose last admin is erased is administratively dead: granting the admin role
// is itself an admin action, so no remaining user could restore it.
func TestErasingRefusesToRemoveTheLastAdmin(t *testing.T) {
	f, ctx := support.SharedTenant(t, "eraselastadmin")
	admin, _ := inviteServices(t, f)

	only, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "sole.admin@example.com", Role: auth.RoleAdmin, Password: "a long enough passphrase",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	_, err = admin.EraseUser(ctx, &pb.EraseUserRequest{
		UserId: only.GetUserId(), ConfirmEmail: "sole.admin@example.com",
	})
	if err == nil {
		t.Fatal("the tenant's last administrator was erased")
	}

	// With a second active admin the same call is permitted.
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "second.admin@example.com", Role: auth.RoleAdmin,
		Password: "another long passphrase",
	}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if _, err := admin.EraseUser(ctx, &pb.EraseUserRequest{
		UserId: only.GetUserId(), ConfirmEmail: "sole.admin@example.com",
	}); err != nil {
		t.Errorf("erasing one of two admins was refused: %v", err)
	}
}

// What erasure must NOT destroy. Entries carry the actor's email as well as their id,
// so the record of what someone did outlives the account that did it. If this fails,
// erasing a user has quietly become a way to launder their history.
func TestErasingAUserLeavesTheirAuditTrailIntact(t *testing.T) {
	f, ctx := support.SharedTenant(t, "eraseaudit")
	admin, _ := inviteServices(t, f)

	// Every call below runs as an authenticated admin. Without claims on the context the
	// audit writer has no actor, every record fails validation, and this test would pass
	// or fail on an empty trail rather than on what erasure actually does.
	actor, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "auditor.admin@example.com", Role: auth.RoleAdmin,
		Password: "a long enough passphrase",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	ctx = actingAs(ctx, actor)

	profile := invitedUser(t, admin, ctx, "traceable@example.com")
	before, err := f.Audit.List(ctx, chdata.ListFilter{
		From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Limit: 500,
	})
	if err != nil {
		t.Fatalf("Audit.List() error = %v", err)
	}

	if _, err := admin.EraseUser(ctx, &pb.EraseUserRequest{
		UserId: profile.GetUserId(), ConfirmEmail: "traceable@example.com",
	}); err != nil {
		t.Fatalf("EraseUser() error = %v", err)
	}

	after, err := f.Audit.List(ctx, chdata.ListFilter{
		From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Limit: 500,
	})
	if err != nil {
		t.Fatalf("Audit.List() error = %v", err)
	}
	if len(after) <= len(before) {
		t.Errorf("audit entries after erase = %d, before = %d; the trail did not grow",
			len(after), len(before))
	}

	var sawErase bool
	for _, entry := range after {
		if entry.Action == audit.ActionUserErase && entry.TargetID == profile.GetUserId() {
			sawErase = true
		}
	}
	if !sawErase {
		t.Error("no user_erase entry records the deletion")
	}
}

// An admin erasing their own account destroys the identity their live token names, and
// every request they make afterwards 401s. There is no way back through the API, so it
// is refused rather than repaired.
func TestErasingRefusesTheCallersOwnAccount(t *testing.T) {
	f, ctx := support.SharedTenant(t, "eraseself")
	admin, _ := inviteServices(t, f)

	me, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "self@example.com", Role: auth.RoleAdmin, Password: "a long enough passphrase",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	// A second admin, so the refusal below is attributable to the self-erase guard and
	// not to the last-administrator one.
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Email: "colleague@example.com", Role: auth.RoleAdmin,
		Password: "another long passphrase",
	}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if _, err := admin.EraseUser(actingAs(ctx, me), &pb.EraseUserRequest{
		UserId: me.GetUserId(), ConfirmEmail: "self@example.com",
	}); err == nil {
		t.Fatal("an administrator erased their own account")
	}

	id, err := uuid.Parse(me.GetUserId())
	if err != nil {
		t.Fatalf("parse user id: %v", err)
	}
	if _, err := f.Users.Get(ctx, id); err != nil {
		t.Errorf("the refused self-erase removed the account anyway: %v", err)
	}
}
