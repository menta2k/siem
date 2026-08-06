package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// ErrEmailTaken is returned when a tenant already has a user with that address.
var ErrEmailTaken = errors.New("clickhouse: a user with that email already exists")

// User is a control-plane user record.
type User struct {
	TenantID     uuid.UUID
	ID           uuid.UUID
	Email        string
	PasswordHash string
	MFASecret    string
	MFAEnabled   bool
	Role         string
	Status       string
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	Version      uint64
}

// User lifecycle states.
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
)

// Active reports whether the user may authenticate.
func (u User) Active() bool { return u.Status == UserStatusActive }

// UserRepo reads and writes user records, always scoped to the context's tenant.
type UserRepo struct {
	client *Client
	locker Locker
}

// NewUserRepo constructs the repository.
func NewUserRepo(client *Client, locker Locker) *UserRepo {
	return &UserRepo{client: client, locker: locker}
}

const userColumns = `tenant_id, user_id, email, password_hash, mfa_secret, mfa_enabled,
	role, status, last_login_at, created_at, version`

// Get loads a user by id within the context's tenant.
func (r *UserRepo) Get(ctx context.Context, userID uuid.UUID) (User, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return User{}, err
	}

	query := fmt.Sprintf(
		`SELECT %s FROM users FINAL WHERE tenant_id = ? AND user_id = ? LIMIT 1`, userColumns)

	return r.scanOne(ctx, query, tenantID, userID)
}

// FindByEmail loads a user by address.
//
// tenantID is an explicit argument here, unlike every other read, because login must
// resolve a user BEFORE a tenant context can exist. This is the one place that
// exception is permitted, and it is why the login flow resolves the tenant first.
func (r *UserRepo) FindByEmail(
	ctx context.Context, tenantID uuid.UUID, email string,
) (User, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM users FINAL WHERE tenant_id = ? AND lower(email) = ? LIMIT 1`, userColumns)

	return r.scanOne(ctx, query, tenantID, normalizeEmail(email))
}

// List returns the tenant's users, ordered by email.
func (r *UserRepo) List(ctx context.Context, limit int32) ([]User, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(
		`SELECT %s FROM users FINAL WHERE tenant_id = ? ORDER BY email LIMIT ?`, userColumns)

	rows, err := r.client.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

// Create inserts a user, enforcing per-tenant email uniqueness under a lock.
func (r *UserRepo) Create(ctx context.Context, u User) (User, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return User{}, err
	}
	u.TenantID = tenantID
	u.Email = normalizeEmail(u.Email)

	// ClickHouse cannot enforce uniqueness, so the check-then-insert is serialised
	// per (tenant, email). Without the lock two concurrent signups would both see no
	// existing row and both insert.
	release, err := r.locker.Lock(ctx, fmt.Sprintf("user:%s:%s", tenantID, u.Email))
	if err != nil {
		return User{}, err
	}
	defer release()

	switch _, err := r.FindByEmail(ctx, tenantID, u.Email); {
	case err == nil:
		return User{}, ErrEmailTaken
	case !errors.Is(err, ErrNotFound):
		return User{}, err
	}

	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Status == "" {
		u.Status = UserStatusActive
	}
	u.CreatedAt, u.Version = time.Now().UTC(), 1

	if err := r.insert(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

// Update writes a new version of a user. mutate receives a copy.
func (r *UserRepo) Update(
	ctx context.Context, userID uuid.UUID, mutate func(User) User,
) (User, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return User{}, err
	}

	release, err := r.locker.Lock(ctx, fmt.Sprintf("user:%s:%s", tenantID, userID))
	if err != nil {
		return User{}, err
	}
	defer release()

	current, err := r.Get(ctx, userID)
	if err != nil {
		return User{}, err
	}

	updated := mutate(current)
	// Identity and creation time are not the caller's to change.
	updated.TenantID, updated.ID = current.TenantID, current.ID
	updated.CreatedAt = current.CreatedAt
	updated.Email = normalizeEmail(updated.Email)
	updated.Version = current.Version + 1

	if err := r.insert(ctx, updated); err != nil {
		return User{}, err
	}
	return updated, nil
}

// RecordLogin stamps the last successful login time.
func (r *UserRepo) RecordLogin(ctx context.Context, userID uuid.UUID, at time.Time) error {
	_, err := r.Update(ctx, userID, func(u User) User {
		stamped := at.UTC()
		u.LastLoginAt = &stamped
		return u
	})
	return err
}

func (r *UserRepo) insert(ctx context.Context, u User) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO users")
	if err != nil {
		return err
	}
	if err := batch.Append(
		u.TenantID, u.ID, u.Email, u.PasswordHash, u.MFASecret, u.MFAEnabled,
		u.Role, u.Status, u.LastLoginAt, u.CreatedAt, u.Version,
	); err != nil {
		return fmt.Errorf("append user %s: %w", u.ID, err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert user %s: %w", u.ID, err)
	}
	return nil
}

func (r *UserRepo) scanOne(ctx context.Context, query string, args ...any) (User, error) {
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return User{}, fmt.Errorf("load user: %w", err)
		}
		return User{}, ErrNotFound
	}
	return scanUser(rows)
}

// rowScanner is the minimal scanning surface shared by driver.Rows and driver.Row.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (User, error) {
	var u User
	err := row.Scan(&u.TenantID, &u.ID, &u.Email, &u.PasswordHash, &u.MFASecret,
		&u.MFAEnabled, &u.Role, &u.Status, &u.LastLoginAt, &u.CreatedAt, &u.Version)
	if err != nil {
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}

// normalizeEmail lowercases and trims, so uniqueness is not defeated by casing.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ErrAmbiguousLogin reports an address present in more than one tenant. Login cannot
// proceed, because any resolution would be a guess about which tenant's data the
// caller is entitled to see.
var ErrAmbiguousLogin = errors.New("the login address exists in more than one tenant")

// ResolveByEmail finds the tenant that owns a login address.
//
// This is the ONLY query in the system that reads the users table without a tenant
// predicate, and it exists because login is the one operation that has no tenant yet:
// the caller supplies an email and a password, and the tenant is what we are trying to
// discover. Everything downstream is scoped normally.
//
// AMBIGUITY IS AN ERROR, not a choice. If the same address exists in two tenants there
// is no correct answer, and picking one — the first row, the newest, whatever the sort
// order happens to yield — authenticates someone into a tenant that may not be theirs.
// That is a cross-tenant data exposure produced by a tie-break, so it fails instead.
func (r *UserRepo) ResolveByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	normalized := normalizeEmail(email)
	if normalized == "" {
		return uuid.Nil, ErrNotFound
	}

	rows, err := r.client.Query(ctx,
		`SELECT DISTINCT tenant_id FROM users FINAL
		 WHERE lower(email) = ? AND status = 'active' LIMIT 2`, normalized)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve tenant for login: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var found []uuid.UUID
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			return uuid.Nil, fmt.Errorf("scan tenant for login: %w", err)
		}
		found = append(found, tenantID)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, fmt.Errorf("resolve tenant for login: %w", err)
	}

	switch len(found) {
	case 0:
		return uuid.Nil, ErrNotFound
	case 1:
		return found[0], nil
	default:
		return uuid.Nil, ErrAmbiguousLogin
	}
}
