package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// ErrInviteSpent is returned when an invite has already been redeemed. It is separate
// from ErrNotFound so the service can audit a replay attempt distinctly; the caller
// still sees one indistinguishable message.
var ErrInviteSpent = errors.New("clickhouse: the invite has already been redeemed")

// Invite is a one-time account setup record.
//
// It never holds the token, only the hash of its secret half. An issued token exists in
// exactly one place after the response that carried it: the invited user's hands.
type Invite struct {
	TenantID  uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	Email     string
	IssuedBy  *uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
	// RedeemedAt is nil while the invite is still spendable.
	RedeemedAt *time.Time
	Version    uint64
}

// Spent reports whether the invite has already been used.
func (i Invite) Spent() bool { return i.RedeemedAt != nil }

// Expired reports whether the invite is past its deadline at the given instant.
func (i Invite) Expired(now time.Time) bool { return !now.Before(i.ExpiresAt) }

// Redeemable reports whether the invite may still be spent.
func (i Invite) Redeemable(now time.Time) bool { return !i.Spent() && !i.Expired(now) }

// InviteRepo reads and writes account setup invitations.
type InviteRepo struct {
	client *Client
	locker Locker
}

// NewInviteRepo constructs the repository.
func NewInviteRepo(client *Client, locker Locker) *InviteRepo {
	return &InviteRepo{client: client, locker: locker}
}

const inviteColumns = `tenant_id, user_id, token_hash, email, issued_by, issued_at,
	expires_at, redeemed_at, version`

// inviteLockKey serialises writes for one user's invite. Issue and Redeem share it, so
// a re-issue racing a redemption cannot both spend the old token and install a new one.
func inviteLockKey(tenantID, userID uuid.UUID) string {
	return fmt.Sprintf("invite:%s:%s", tenantID, userID)
}

// Issue stores an invite, superseding any previous one for the same user.
//
// Superseding is the point: the row is keyed by (tenant, user) in a ReplacingMergeTree,
// so re-issuing an invite invalidates the token that came before it. An admin who
// re-sends a setup link has, by that act, killed the old one.
func (r *InviteRepo) Issue(ctx context.Context, invite Invite) (Invite, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Invite{}, err
	}
	if invite.UserID == uuid.Nil {
		return Invite{}, errors.New("clickhouse: an invite needs a user id")
	}
	invite.TenantID = tenantID

	release, err := r.locker.Lock(ctx, inviteLockKey(tenantID, invite.UserID))
	if err != nil {
		return Invite{}, err
	}
	defer release()

	// Version continues the existing row's sequence. Restarting at 1 would let
	// ReplacingMergeTree keep the SUPERSEDED invite as the winner, leaving a token the
	// admin believes they revoked still live.
	next := uint64(1)
	switch current, err := r.get(ctx, tenantID, invite.UserID); {
	case err == nil:
		next = current.Version + 1
	case !errors.Is(err, ErrNotFound):
		return Invite{}, err
	}

	invite.Email = normalizeEmail(invite.Email)
	invite.IssuedAt = time.Now().UTC()
	invite.RedeemedAt = nil
	invite.Version = next

	if err := r.insert(ctx, invite); err != nil {
		return Invite{}, err
	}
	return invite, nil
}

// Find loads the invite for a user.
//
// tenantID is an explicit argument rather than being read from the context, for the
// same reason UserRepo.FindByEmail takes one: redemption happens BEFORE any login, so
// there is no tenant on the context yet. The tenant comes from the presented token,
// which is why the token carries it — and a token naming a tenant the holder has no
// secret for still fails, because the secret is checked against this row's hash.
func (r *InviteRepo) Find(
	ctx context.Context, tenantID, userID uuid.UUID,
) (Invite, error) {
	return r.get(ctx, tenantID, userID)
}

// MarkRedeemed spends the invite, so no later presentation of the same token succeeds.
//
// Callers MUST do this before writing the new password. If the order were reversed, a
// failure between the two writes would leave a live token that had already changed a
// password once and could do so again.
func (r *InviteRepo) MarkRedeemed(
	ctx context.Context, tenantID, userID uuid.UUID, at time.Time,
) (Invite, error) {
	release, err := r.locker.Lock(ctx, inviteLockKey(tenantID, userID))
	if err != nil {
		return Invite{}, err
	}
	defer release()

	current, err := r.get(ctx, tenantID, userID)
	if err != nil {
		return Invite{}, err
	}
	// Re-checked under the lock. The caller checked too, but that read was not
	// serialised against a concurrent redemption of the same token.
	if current.Spent() {
		return Invite{}, ErrInviteSpent
	}

	spent := at.UTC()
	current.RedeemedAt = &spent
	current.Version++

	if err := r.insert(ctx, current); err != nil {
		return Invite{}, err
	}
	return current, nil
}

func (r *InviteRepo) get(
	ctx context.Context, tenantID, userID uuid.UUID,
) (Invite, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM user_invites FINAL
		 WHERE tenant_id = ? AND user_id = ? LIMIT 1`, inviteColumns)

	rows, err := r.client.Query(ctx, query, tenantID, userID)
	if err != nil {
		return Invite{}, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Invite{}, fmt.Errorf("load invite: %w", err)
		}
		return Invite{}, ErrNotFound
	}
	return scanInvite(rows)
}

func (r *InviteRepo) insert(ctx context.Context, i Invite) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO user_invites")
	if err != nil {
		return err
	}
	if err := batch.Append(
		i.TenantID, i.UserID, i.TokenHash, i.Email, i.IssuedBy, i.IssuedAt,
		i.ExpiresAt, i.RedeemedAt, i.Version,
	); err != nil {
		return fmt.Errorf("append invite for user %s: %w", i.UserID, err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert invite for user %s: %w", i.UserID, err)
	}
	return nil
}

func scanInvite(row rowScanner) (Invite, error) {
	var i Invite
	err := row.Scan(&i.TenantID, &i.UserID, &i.TokenHash, &i.Email, &i.IssuedBy,
		&i.IssuedAt, &i.ExpiresAt, &i.RedeemedAt, &i.Version)
	if err != nil {
		return Invite{}, fmt.Errorf("scan invite: %w", err)
	}
	return i, nil
}
