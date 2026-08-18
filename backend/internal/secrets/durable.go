package secrets

import (
	"context"
	"fmt"
	"time"
)

// The durable copy of a secret, sealed.
//
// It exists because the cache holding the only copy is a single restart away from taking
// every feed down at once, which is not a hypothetical: it happened, and it stopped
// ingestion for two hours. See the migration that creates the table for why writing
// ciphertext here does not reopen what the package rule was protecting against.

// Rows is the query surface this store needs. It is deliberately tiny so the store can be
// tested without a database and wired to the ClickHouse client without importing it.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

// DB is the database surface the durable store reads and writes through.
type DB interface {
	Query(ctx context.Context, query string, args ...any) (Rows, error)
	Exec(ctx context.Context, query string, args ...any) error
}

// DurableStore keeps sealed secrets in the analytical store.
type DurableStore struct {
	db     DB
	sealer *Sealer
	now    func() time.Time
}

// NewDurableStore constructs the store. A nil sealer is refused rather than defaulted:
// storing these unsealed is the thing the package forbids.
func NewDurableStore(db DB, sealer *Sealer) (*DurableStore, error) {
	if db == nil {
		return nil, fmt.Errorf("secrets: a database is required for the durable store")
	}
	if sealer == nil {
		return nil, ErrKeyRequired
	}
	return &DurableStore{db: db, sealer: sealer, now: time.Now}, nil
}

// Put seals a secret and writes it under a fresh reference.
func (s *DurableStore) Put(ctx context.Context, purpose, secret string) (string, error) {
	ref := NewReference(purpose)
	if err := s.write(ctx, ref, purpose, secret); err != nil {
		return "", err
	}
	return ref, nil
}

// PutRef seals a secret under a reference that already exists.
//
// Needed because the cache and the durable copy have to agree on the reference: a
// credential restored, or written through from a cache that already minted one, keeps the
// reference the feeds table is pointing at.
func (s *DurableStore) PutRef(ctx context.Context, ref, purpose, secret string) error {
	if ref == "" {
		return fmt.Errorf("secrets: a reference is required")
	}
	return s.write(ctx, ref, purpose, secret)
}

func (s *DurableStore) write(ctx context.Context, ref, purpose, secret string) error {
	sealed, err := s.sealer.Seal(secret)
	if err != nil {
		return err
	}

	// The version is the write's own timestamp, so the newest write wins whatever order
	// the parts merge in — which is what makes a rotation final rather than a race.
	now := s.now().UTC()
	err = s.db.Exec(ctx,
		`INSERT INTO feed_secrets (ref, sealed, purpose, updated_at, deleted, version)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ref, sealed, purpose, now, false, uint64(now.UnixNano()))
	if err != nil {
		// The reference is safe to name; the secret never is.
		return fmt.Errorf("secrets: store %s durably: %w", ref, err)
	}
	return nil
}

// Resolve reads and unseals a secret.
func (s *DurableStore) Resolve(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", ErrNotFound
	}

	rows, err := s.db.Query(ctx,
		`SELECT sealed, deleted FROM feed_secrets FINAL WHERE ref = ? LIMIT 1`, ref)
	if err != nil {
		return "", fmt.Errorf("secrets: read %s durably: %w", ref, err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("secrets: read %s durably: %w", ref, err)
		}
		return "", ErrNotFound
	}

	var (
		sealed  string
		deleted bool
	)
	if err := rows.Scan(&sealed, &deleted); err != nil {
		return "", fmt.Errorf("secrets: scan %s: %w", ref, err)
	}
	if deleted || sealed == "" {
		return "", ErrNotFound
	}
	return s.sealer.Open(sealed)
}

// Delete tombstones a secret.
//
// A tombstone rather than a mutation: ALTER DELETE is asynchronous, and a rotated
// credential has to stop resolving at a moment the caller can point at.
func (s *DurableStore) Delete(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}

	now := s.now().UTC()
	err := s.db.Exec(ctx,
		`INSERT INTO feed_secrets (ref, sealed, purpose, updated_at, deleted, version)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ref, "", "deleted", now, true, uint64(now.UnixNano()))
	if err != nil {
		return fmt.Errorf("secrets: delete %s durably: %w", ref, err)
	}
	return nil
}
