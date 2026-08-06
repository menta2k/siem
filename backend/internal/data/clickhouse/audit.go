package clickhouse

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/audit"
	"github.com/menta2k/siem/internal/tenancy"
)

// AuditRepo appends to and reads the audit trail.
//
// There is deliberately no Update and no Delete method. The trail records what was
// done to the system, so the system must have no way to rewrite it (FR-035). The
// table is a plain MergeTree with no version column, so even a stray insert of the
// same key cannot replace an existing entry.
type AuditRepo struct {
	client *Client
	locker Locker
}

// NewAuditRepo constructs the repository.
func NewAuditRepo(client *Client, locker Locker) *AuditRepo {
	return &AuditRepo{client: client, locker: locker}
}

const auditColumns = `tenant_id, entry_id, occurred_at, actor_user_id, actor_email, source_ip,
	action, target_type, target_id, before_value, after_value, result, detail,
	prev_hash, entry_hash`

// Append writes one audit entry, chained to the tenant's most recent one.
//
// The read-then-chain-then-write sequence is serialised per tenant: two concurrent
// writers that both read the same predecessor would create a fork, and the chain
// would fail to verify even though nothing was tampered with.
func (r *AuditRepo) Append(ctx context.Context, record audit.Record) (audit.Entry, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return audit.Entry{}, err
	}

	release, err := r.locker.Lock(ctx, "audit:"+tenantID.String())
	if err != nil {
		return audit.Entry{}, err
	}
	defer release()

	prevHash, err := r.latestHash(ctx, tenantID)
	if err != nil {
		return audit.Entry{}, err
	}

	entry, err := audit.Chain(tenantID, prevHash, time.Now().UTC(), record)
	if err != nil {
		return audit.Entry{}, err
	}
	if err := r.insert(ctx, entry); err != nil {
		return audit.Entry{}, err
	}
	return entry, nil
}

// AppendFor writes an entry for a tenant resolved outside a tenant context.
//
// Needed for failed logins: the attempt must be recorded, but a failed login never
// establishes a tenant context. Restricted to the auth path.
func (r *AuditRepo) AppendFor(
	ctx context.Context, tenantID uuid.UUID, record audit.Record,
) (audit.Entry, error) {
	return r.Append(tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenantID}), record)
}

// latestHash returns the most recent entry hash for a tenant, or "" to start a chain.
func (r *AuditRepo) latestHash(ctx context.Context, tenantID uuid.UUID) (string, error) {
	const query = `SELECT entry_hash FROM audit_entries
		WHERE tenant_id = ?
		ORDER BY occurred_at DESC, entry_id DESC
		LIMIT 1`

	rows, err := r.client.Query(ctx, query, tenantID)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("read latest audit hash: %w", err)
		}
		return "", nil // first entry for this tenant
	}

	var hash string
	if err := rows.Scan(&hash); err != nil {
		return "", fmt.Errorf("scan latest audit hash: %w", err)
	}
	return hash, nil
}

// ListFilter narrows an audit query.
type ListFilter struct {
	From       time.Time
	To         time.Time
	Action     string
	ActorEmail string
	Limit      int32
}

// List returns entries in chronological order for the context's tenant.
//
// Ascending order is deliberate even though most listings are newest-first: the
// caller verifies the hash chain, and a chain can only be walked forwards.
func (r *AuditRepo) List(ctx context.Context, f ListFilter) ([]audit.Entry, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`SELECT %s FROM audit_entries
		WHERE tenant_id = ? AND occurred_at >= ? AND occurred_at <= ?`, auditColumns)
	args := []any{tenantID, f.From.UTC(), f.To.UTC()}

	if f.Action != "" {
		query += " AND action = ?"
		args = append(args, f.Action)
	}
	if f.ActorEmail != "" {
		query += " AND actor_email = ?"
		args = append(args, normalizeEmail(f.ActorEmail))
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	query += " ORDER BY occurred_at ASC, entry_id ASC LIMIT ?"
	args = append(args, limit)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []audit.Entry
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit entries: %w", err)
	}
	return entries, nil
}

// VerifyChain walks the tenant's chain over a range and reports any break.
//
// The range may begin mid-chain — an operator looking at last week's audit page is the
// normal case — so this checks what such a slice can actually prove: that every entry
// still hashes to its own content and still links to the one before it.
func (r *AuditRepo) VerifyChain(ctx context.Context, from, to time.Time) error {
	entries, err := r.List(ctx, ListFilter{From: from, To: to, Limit: 10000})
	if err != nil {
		return err
	}
	return audit.VerifyRange(entries)
}

func (r *AuditRepo) insert(ctx context.Context, e audit.Entry) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO audit_entries")
	if err != nil {
		return err
	}

	sourceIP := e.SourceIP
	if sourceIP == nil {
		sourceIP = net.IPv6zero
	}

	if err := batch.Append(
		e.TenantID, e.EntryID, e.OccurredAt, e.ActorUserID, e.ActorEmail, sourceIP,
		string(e.Action), e.TargetType, e.TargetID, e.BeforeValue, e.AfterValue,
		string(e.Result), e.Detail, e.PrevHash, e.EntryHash,
	); err != nil {
		return fmt.Errorf("append audit entry %s: %w", e.EntryID, err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert audit entry %s: %w", e.EntryID, err)
	}
	return nil
}

func scanAuditEntry(row rowScanner) (audit.Entry, error) {
	var (
		e        audit.Entry
		action   string
		result   string
		sourceIP net.IP
	)
	err := row.Scan(&e.TenantID, &e.EntryID, &e.OccurredAt, &e.ActorUserID, &e.ActorEmail,
		&sourceIP, &action, &e.TargetType, &e.TargetID, &e.BeforeValue, &e.AfterValue,
		&result, &e.Detail, &e.PrevHash, &e.EntryHash)
	if err != nil {
		return audit.Entry{}, fmt.Errorf("scan audit entry: %w", err)
	}

	e.Action, e.Result = audit.Action(action), audit.Result(result)
	// The zero address is how "no source recorded" is stored; restore it as absent so
	// the rehash matches what Chain computed.
	if !sourceIP.Equal(net.IPv6zero) {
		e.SourceIP = sourceIP
	}
	return e, nil
}
