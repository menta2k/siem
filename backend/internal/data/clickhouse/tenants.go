package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// ErrNotFound is returned when a row does not exist for the caller's tenant.
//
// A row belonging to ANOTHER tenant also produces ErrNotFound rather than a
// permission error, so the existence of a neighbouring tenant's data is not
// observable through response codes (SC-009).
var ErrNotFound = errors.New("clickhouse: not found")

// Tenant is a control-plane tenant record.
type Tenant struct {
	ID                      uuid.UUID
	Name                    string
	Status                  string
	RawRetentionDays        uint16
	CorrelatedRetentionDays uint16
	AlertRetentionDays      uint16
	RedactedFields          []string
	CorrelationWindowMS     uint32
	LatenessBoundMS         uint32
	ScoreConflictThreshold  float32
	CreatedAt               time.Time
	UpdatedAt               time.Time
	Version                 uint64
}

// Active reports whether the tenant may currently operate.
func (t Tenant) Active() bool { return t.Status == TenantStatusActive }

// Tenant lifecycle states.
const (
	TenantStatusActive    = "active"
	TenantStatusSuspended = "suspended"
)

// TenantRepo reads and writes tenant records.
//
// Every read uses FINAL. ReplacingMergeTree deduplication is eventual, so a read
// without it can return both the pre- and post-update row — which for a tenant would
// mean retention settings flapping between old and new values.
type TenantRepo struct {
	client *Client
	locker Locker
}

// NewTenantRepo constructs the repository.
func NewTenantRepo(client *Client, locker Locker) *TenantRepo {
	return &TenantRepo{client: client, locker: locker}
}

const tenantColumns = `tenant_id, name, status, raw_retention_days, correlated_retention_days,
	alert_retention_days, redacted_fields, correlation_window_ms, lateness_bound_ms,
	score_conflict_threshold, created_at, updated_at, version`

// Get loads the tenant in context. It takes no tenant argument by design: the caller
// cannot ask for a tenant other than its own.
func (r *TenantRepo) Get(ctx context.Context) (Tenant, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Tenant{}, err
	}
	return r.getByID(ctx, tenantID)
}

// GetByID loads a tenant by id. Reserved for the authentication path, which must
// resolve a tenant BEFORE a tenant context exists, and for the seed tool. Every
// other caller uses Get.
func (r *TenantRepo) GetByID(ctx context.Context, id uuid.UUID) (Tenant, error) {
	return r.getByID(ctx, id)
}

func (r *TenantRepo) getByID(ctx context.Context, id uuid.UUID) (Tenant, error) {
	query := fmt.Sprintf(`SELECT %s FROM tenants FINAL WHERE tenant_id = ? LIMIT 1`, tenantColumns)

	t, err := scanTenant(r.client.QueryRow(ctx, query, id))
	if err != nil {
		if isNoRows(err) {
			return Tenant{}, ErrNotFound
		}
		return Tenant{}, fmt.Errorf("load tenant %s: %w", id, err)
	}
	return t, nil
}

// scanTenant reads one row. Shared by the point read and the listing so the column
// order is stated once — two copies drift the moment a column is added.
func scanTenant(row rowScanner) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Name, &t.Status, &t.RawRetentionDays, &t.CorrelatedRetentionDays,
		&t.AlertRetentionDays, &t.RedactedFields, &t.CorrelationWindowMS, &t.LatenessBoundMS,
		&t.ScoreConflictThreshold, &t.CreatedAt, &t.UpdatedAt, &t.Version)
	return t, err
}

// IsActive reports whether a tenant may operate. Used by the auth middleware.
func (r *TenantRepo) IsActive(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	t, err := r.getByID(ctx, tenantID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return t.Active(), nil
}

// Create inserts a new tenant. Uniqueness on name is enforced under a lock because
// ClickHouse has no unique constraint (see research.md R6).
func (r *TenantRepo) Create(ctx context.Context, t Tenant) (Tenant, error) {
	release, err := r.locker.Lock(ctx, "tenant:name:"+t.Name)
	if err != nil {
		return Tenant{}, err
	}
	defer release()

	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now().UTC()
	t.CreatedAt, t.UpdatedAt, t.Version = now, now, 1
	if t.Status == "" {
		t.Status = TenantStatusActive
	}

	if err := r.insert(ctx, t); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Update writes a new version of the tenant in context.
//
// The whole row is re-inserted with an incremented version rather than mutated:
// ClickHouse ALTER UPDATE is an expensive background mutation, and versioned inserts
// are how ReplacingMergeTree is meant to be used.
func (r *TenantRepo) Update(ctx context.Context, mutate func(Tenant) Tenant) (Tenant, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Tenant{}, err
	}

	release, err := r.locker.Lock(ctx, "tenant:"+tenantID.String())
	if err != nil {
		return Tenant{}, err
	}
	defer release()

	current, err := r.getByID(ctx, tenantID)
	if err != nil {
		return Tenant{}, err
	}

	// mutate receives a copy, so it cannot modify the stored value in place.
	updated := mutate(current)
	updated.ID = current.ID
	updated.CreatedAt = current.CreatedAt
	updated.UpdatedAt = time.Now().UTC()
	updated.Version = current.Version + 1

	if err := r.insert(ctx, updated); err != nil {
		return Tenant{}, err
	}
	return updated, nil
}

func (r *TenantRepo) insert(ctx context.Context, t Tenant) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO tenants")
	if err != nil {
		return err
	}
	if t.RedactedFields == nil {
		t.RedactedFields = []string{}
	}

	if err := batch.Append(
		t.ID, t.Name, t.Status, t.RawRetentionDays, t.CorrelatedRetentionDays,
		t.AlertRetentionDays, t.RedactedFields, t.CorrelationWindowMS, t.LatenessBoundMS,
		t.ScoreConflictThreshold, t.CreatedAt, t.UpdatedAt, t.Version,
	); err != nil {
		return fmt.Errorf("append tenant %s: %w", t.ID, err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert tenant %s: %w", t.ID, err)
	}
	return nil
}

// ListAll returns every tenant.
//
// Deliberately unscoped: the retention worker has no request to inherit a tenant from
// and must reconcile all of them. Every caller is a background worker, and each one
// re-scopes per tenant before touching that tenant's data.
func (r *TenantRepo) ListAll(ctx context.Context) ([]Tenant, error) {
	rows, err := r.client.Query(ctx,
		"SELECT "+tenantColumns+" FROM tenants FINAL ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tenants []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}
