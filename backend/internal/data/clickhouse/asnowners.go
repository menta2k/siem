package clickhouse

import (
	"context"
	"fmt"
	"time"
)

// ASNOwner is one network's registry entry.
type ASNOwner struct {
	ASN     uint32
	Name    string
	Country string
}

// ASNOwnerRepo reads and replaces the AS-number-to-owner table.
//
// The only repository here with NO tenant predicate, and deliberately so: who owns
// AS8866 is a fact about the internet rather than about anyone's traffic. Nothing in the
// table derives from a tenant's events, so there is nothing to leak between them, and
// scoping it per tenant would store the same 90,000 rows once per customer.
type ASNOwnerRepo struct {
	client *Client
}

// NewASNOwnerRepo constructs the repository.
func NewASNOwnerRepo(client *Client) *ASNOwnerRepo {
	return &ASNOwnerRepo{client: client}
}

// asnOwnerBatchSize bounds one insert. The full table is ~90,000 rows, which is small
// enough to send whole, but the chunking keeps a future growth in the published file
// from turning one refresh into one enormous statement.
const asnOwnerBatchSize = 20_000

// Replace writes the current snapshot.
//
// It INSERTS rather than truncating first, and the engine does the rest: the table is a
// ReplacingMergeTree keyed on asn and versioned by updated_at, so re-importing an
// unchanged network collapses to one row and a renamed one keeps the newer name.
//
// Truncating would open a window — however brief — in which the table is empty while
// queries are running, and a panel that renders "AS8866" with no name for two seconds
// every night is a worse outcome than carrying a stale name for one refresh cycle.
//
// An EMPTY snapshot is refused. A download that yielded nothing is a failed download,
// and writing it would be indistinguishable from the upstream having deleted the
// internet.
func (r *ASNOwnerRepo) Replace(ctx context.Context, owners []ASNOwner, at time.Time) error {
	if len(owners) == 0 {
		return fmt.Errorf("refusing to replace the asn owner table with an empty snapshot")
	}

	stamp := at.UTC()
	for start := 0; start < len(owners); start += asnOwnerBatchSize {
		end := min(start+asnOwnerBatchSize, len(owners))
		if err := r.insertChunk(ctx, owners[start:end], stamp); err != nil {
			return err
		}
	}
	return nil
}

func (r *ASNOwnerRepo) insertChunk(
	ctx context.Context, owners []ASNOwner, stamp time.Time,
) error {
	// Columns are NAMED, so adding one to the table does not silently rebind these
	// values to the wrong destinations.
	batch, err := r.client.PrepareBatch(ctx,
		"INSERT INTO asn_owners (asn, name, country, updated_at)")
	if err != nil {
		return err
	}
	for _, owner := range owners {
		if err := batch.Append(owner.ASN, owner.Name, owner.Country, stamp); err != nil {
			return fmt.Errorf("append asn %d: %w", owner.ASN, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert %d asn owners: %w", len(owners), err)
	}
	return nil
}

// NamesFor resolves a set of AS numbers to their owners' names.
//
// Returns only what it FINDS. A missing ASN is not an error: the table is refreshed
// from a third-party file that lags new allocations, and a panel must render a network
// it cannot name rather than failing.
func (r *ASNOwnerRepo) NamesFor(ctx context.Context, asns []uint32) (map[uint32]string, error) {
	if len(asns) == 0 {
		return map[uint32]string{}, nil
	}

	// FINAL because the engine collapses duplicate asn rows on merge, which happens in
	// the background: without it a network refreshed under a new name can briefly
	// resolve to both, and the caller would take whichever row came back first.
	rows, err := r.client.Query(ctx,
		"SELECT asn, name FROM asn_owners FINAL WHERE asn IN (?)", asns)
	if err != nil {
		return nil, fmt.Errorf("resolve asn owners: %w", err)
	}
	defer func() { _ = rows.Close() }()

	names := make(map[uint32]string, len(asns))
	for rows.Next() {
		var (
			asn  uint32
			name string
		)
		if err := rows.Scan(&asn, &name); err != nil {
			return nil, fmt.Errorf("scan asn owner: %w", err)
		}
		names[asn] = name
	}
	return names, rows.Err()
}

// Count reports how many networks are known, which is what the refresh worker logs and
// what an operator checks when names stop appearing.
func (r *ASNOwnerRepo) Count(ctx context.Context) (uint64, error) {
	rows, err := r.client.Query(ctx, "SELECT count() FROM asn_owners FINAL")
	if err != nil {
		return 0, fmt.Errorf("count asn owners: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var count uint64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, fmt.Errorf("scan asn owner count: %w", err)
		}
	}
	return count, rows.Err()
}
