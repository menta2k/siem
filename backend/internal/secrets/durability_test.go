package secrets

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// The incident these tests describe: Redis holds the feed credentials and runs without
// persistence, so one restart emptied it, every feed failed authentication at once, and
// ingestion stopped for two hours with nothing anywhere to restore from.

func sealer(t *testing.T) *Sealer {
	t.Helper()
	key := make([]byte, KeyBytes)
	for i := range key {
		key[i] = byte(i)
	}
	built, err := NewSealer(key)
	if err != nil {
		t.Fatalf("build sealer: %v", err)
	}
	return built
}

// fakeDB is the durable store's database, in memory.
type fakeDB struct {
	mu sync.Mutex
	// queries counts reads, because "how often does this run on the ingest hot path" is
	// itself a requirement.
	queries int
	rows    map[string]fakeRow
	err     error
}

type fakeRow struct {
	sealed  string
	deleted bool
	version uint64
}

func newFakeDB() *fakeDB { return &fakeDB{rows: map[string]fakeRow{}} }

func (d *fakeDB) Exec(_ context.Context, _ string, args ...any) error {
	if d.err != nil {
		return d.err
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	ref, _ := args[0].(string)
	sealed, _ := args[1].(string)
	deleted, _ := args[4].(bool)
	version, _ := args[5].(uint64)

	// ReplacingMergeTree keeps the highest version, which is what makes a rotation final.
	if existing, ok := d.rows[ref]; ok && existing.version > version {
		return nil
	}
	d.rows[ref] = fakeRow{sealed: sealed, deleted: deleted, version: version}
	return nil
}

func (d *fakeDB) Query(_ context.Context, _ string, args ...any) (Rows, error) {
	d.mu.Lock()
	d.queries++
	err := d.err
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ref, _ := args[0].(string)
	row, ok := d.rows[ref]
	return &fakeRows{row: row, present: ok}, nil
}

type fakeRows struct {
	row     fakeRow
	present bool
	read    bool
}

func (r *fakeRows) Next() bool {
	if !r.present || r.read {
		return false
	}
	r.read = true
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	sealed, ok := dest[0].(*string)
	if !ok {
		return errors.New("unexpected destination")
	}
	deleted, ok := dest[1].(*bool)
	if !ok {
		return errors.New("unexpected destination")
	}
	*sealed, *deleted = r.row.sealed, r.row.deleted
	return nil
}

func (r *fakeRows) Err() error   { return nil }
func (r *fakeRows) Close() error { return nil }

// memoryCache stands in for Redis, including the part that matters: it can be emptied.
type memoryCache struct {
	mu      sync.Mutex
	entries map[string]string
	writes  int
}

func newMemoryCache() *memoryCache {
	return &memoryCache{entries: map[string]string{}}
}

func (c *memoryCache) Put(ctx context.Context, purpose, secret string) (string, error) {
	ref := NewReference(purpose)
	return ref, c.PutRef(ctx, ref, purpose, secret)
}

func (c *memoryCache) PutRef(_ context.Context, ref, _, secret string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ref] = secret
	c.writes++
	return nil
}

func (c *memoryCache) Resolve(_ context.Context, ref string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	secret, ok := c.entries[ref]
	if !ok {
		return "", ErrNotFound
	}
	return secret, nil
}

func (c *memoryCache) Delete(_ context.Context, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ref)
	return nil
}

func (c *memoryCache) flushAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]string{}
}

func tiered(t *testing.T) (*Tiered, *memoryCache, *fakeDB) {
	t.Helper()
	cache, db := newMemoryCache(), newFakeDB()
	durable, err := NewDurableStore(db, sealer(t))
	if err != nil {
		t.Fatalf("build durable store: %v", err)
	}
	return NewTiered(cache, durable, nil), cache, db
}

// THE OUTAGE, IN ONE TEST. The cache is emptied exactly as a Redis restart empties it,
// and the credential still resolves — which is the difference between a feed that keeps
// working and every feed on the platform failing at once.
func TestACredentialSurvivesTheCacheBeingEmptied(t *testing.T) {
	store, cache, _ := tiered(t)
	ctx := context.Background()

	ref, err := store.Put(ctx, "feed-credential", "the-token")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	cache.flushAll()

	got, err := store.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("Resolve after the cache was emptied: %v", err)
	}
	if got != "the-token" {
		t.Errorf("resolved %q, want the stored token", got)
	}
}

// ...and it heals the cache while it is there, so the next thousand deliveries are Redis
// reads again rather than a query each.
func TestResolvingRefillsTheCache(t *testing.T) {
	store, cache, _ := tiered(t)
	ctx := context.Background()

	ref, _ := store.Put(ctx, "feed-credential", "the-token")
	cache.flushAll()

	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if got, err := cache.Resolve(ctx, ref); err != nil || got != "the-token" {
		t.Errorf("cache holds %q (%v), want it refilled", got, err)
	}
}

// A refill is not routine — it means the cache was emptied — so the operator gets told.
func TestARefillIsReported(t *testing.T) {
	cache, db := newMemoryCache(), newFakeDB()
	durable, err := NewDurableStore(db, sealer(t))
	if err != nil {
		t.Fatalf("build durable store: %v", err)
	}

	var reported []string
	store := NewTiered(cache, durable, func(_ context.Context, _, what string) {
		reported = append(reported, what)
	})
	ctx := context.Background()

	ref, _ := store.Put(ctx, "feed-credential", "the-token")
	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(reported) != 0 {
		t.Errorf("a cache hit was reported as %v", reported)
	}

	cache.flushAll()
	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(reported) != 1 || reported[0] != CacheRefilled {
		t.Errorf("reported %v, want the empty cache to be visible as a refill", reported)
	}
}

// The two directions are reported APART. A backfill logged as "the cache was empty" sent
// an operator looking for a Redis problem that had not happened.
func TestABackfillIsNotReportedAsARefill(t *testing.T) {
	cache, db := newMemoryCache(), newFakeDB()
	durable, err := NewDurableStore(db, sealer(t))
	if err != nil {
		t.Fatalf("build durable store: %v", err)
	}

	var reported []string
	store := NewTiered(cache, durable, func(_ context.Context, _, what string) {
		reported = append(reported, what)
	})

	ctx := context.Background()
	ref := NewReference("feed-credential")
	if err := cache.PutRef(ctx, ref, "feed-credential", "the-token"); err != nil {
		t.Fatalf("seed the cache: %v", err)
	}

	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(reported) != 1 || reported[0] != DurableBackfilled {
		t.Errorf("reported %v, want the durable copy being written", reported)
	}
}

// THE ORDER MATTERS AND IT IS NOT SYMMETRIC. A durable write that lands without the cache
// costs one slow read; a cached secret whose durable write failed is a credential that
// works until the next restart and then does not — which is this outage all over again.
func TestAFailedDurableWriteIsNotReportedAsStored(t *testing.T) {
	cache, db := newMemoryCache(), newFakeDB()
	db.err = errors.New("clickhouse is unreachable")
	durable, err := NewDurableStore(db, sealer(t))
	if err != nil {
		t.Fatalf("build durable store: %v", err)
	}
	store := NewTiered(cache, durable, nil)

	if _, err := store.Put(context.Background(), "feed-credential", "the-token"); err == nil {
		t.Fatal("a credential that was never stored durably was reported as stored")
	}
	if len(cache.entries) != 0 {
		t.Error("the cache was written even though the durable copy failed")
	}
}

// A rotated credential has to stop working at a moment the operator can point at.
func TestADeletedCredentialStopsResolving(t *testing.T) {
	store, cache, _ := tiered(t)
	ctx := context.Background()

	ref, _ := store.Put(ctx, "feed-credential", "the-token")
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	cache.flushAll() // the durable copy must not resurrect it

	if _, err := store.Resolve(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want the deleted credential to be gone", err)
	}
}

// WHAT IS WRITTEN IS NOT A CREDENTIAL. The package rule keeps vendor secrets out of the
// analytical store; this is what makes a durable copy compatible with it.
func TestTheStoredValueIsNotTheSecret(t *testing.T) {
	store, _, db := tiered(t)

	ref, err := store.Put(context.Background(), "feed-credential", "super-secret-token")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	stored := db.rows[ref].sealed
	if stored == "" {
		t.Fatal("nothing was written durably")
	}
	if strings.Contains(stored, "super-secret-token") {
		t.Error("the credential was written in the clear")
	}
}

// Sealing the same secret twice must not produce the same text, or a reader could tell
// that two feeds share a credential without being able to read either.
func TestSealingIsNotDeterministic(t *testing.T) {
	s := sealer(t)

	first, err := s.Seal("the-token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := s.Seal("the-token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if first == second {
		t.Error("the same secret sealed twice produced the same text")
	}
	for _, sealed := range []string{first, second} {
		got, err := s.Open(sealed)
		if err != nil || got != "the-token" {
			t.Errorf("Open(%q) = %q, %v", sealed, got, err)
		}
	}
}

// A stored value that cannot be decrypted means the key changed. Reporting it as "no
// secret" would let the next write rotate a working credential out of existence.
func TestAValueSealedWithAnotherKeyIsAnErrorNotAnAbsence(t *testing.T) {
	other := make([]byte, KeyBytes)
	for i := range other {
		other[i] = byte(255 - i)
	}
	otherSealer, err := NewSealer(other)
	if err != nil {
		t.Fatalf("build sealer: %v", err)
	}
	sealed, err := otherSealer.Seal("the-token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = sealer(t).Open(sealed)
	if err == nil {
		t.Fatal("a value sealed with a different key was opened")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a key mismatch was reported as an absent secret")
	}
	if !strings.Contains(err.Error(), "different key") {
		t.Errorf("error = %v, want it to name the cause an operator can act on", err)
	}
}

// A key of the wrong length is a configuration error, not something to default around.
func TestAKeyMustBeTheRightLength(t *testing.T) {
	if _, err := NewSealer([]byte("too short")); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("err = %v, want ErrKeyRequired", err)
	}
	if _, err := DecodeKey("bm90LWJhc2U2NA=="); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("err = %v, want a short key to be refused", err)
	}
}

// Without a key there is no durable copy, and that is the arrangement that failed. The
// service still starts — refusing would turn an upgrade into an outage — but Build says
// so, so the caller cannot fail to notice.
func TestWithoutAKeyTheCallerIsToldTheCopyIsMissing(t *testing.T) {
	cache := newMemoryCache()

	store, err := Build(cache, newFakeDB(), "", nil)
	if !errors.Is(err, ErrNoDurableCopy) {
		t.Errorf("err = %v, want ErrNoDurableCopy", err)
	}
	if store == nil {
		t.Fatal("no store was returned, so the service would not start")
	}

	ref, err := store.Put(context.Background(), "feed-credential", "the-token")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, _ := store.Resolve(context.Background(), ref); got != "the-token" {
		t.Error("the cache-only store does not work")
	}
}

// A key that is present but malformed means somebody INTENDED durability and does not
// have it. That is worth refusing to start over.
func TestAMalformedKeyIsRefused(t *testing.T) {
	if _, err := Build(newMemoryCache(), newFakeDB(), "not-base64!!", nil); err == nil {
		t.Error("a malformed key was accepted")
	}
}

// THE UPGRADE PATH, WHICH IS THE POINT FOR AN EXISTING DEPLOYMENT. Its credentials live
// only in the cache and nothing would ever write them anywhere else, so the next restart
// would lose them exactly as the last one did. The first delivery that resolves each one
// backfills it, with no operator step and no rotation.
func TestACacheOnlyCredentialIsMadeDurableOnFirstUse(t *testing.T) {
	store, cache, db := tiered(t)
	ctx := context.Background()

	// As it exists on a deployment that predates the durable copy.
	ref := NewReference("feed-credential")
	if err := cache.PutRef(ctx, ref, "feed-credential", "the-token"); err != nil {
		t.Fatalf("seed the cache: %v", err)
	}

	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if _, stored := db.rows[ref]; !stored {
		t.Fatal("the credential was not written durably, so the next restart still loses it")
	}

	cache.flushAll()
	if got, err := store.Resolve(ctx, ref); err != nil || got != "the-token" {
		t.Errorf("after the cache was emptied: %q, %v", got, err)
	}
}

// The check costs one query per credential per process, not one per delivery — this runs
// on the ingest hot path.
func TestTheDurableCheckHappensOncePerCredential(t *testing.T) {
	store, cache, db := tiered(t)
	ctx := context.Background()

	ref := NewReference("feed-credential")
	if err := cache.PutRef(ctx, ref, "feed-credential", "the-token"); err != nil {
		t.Fatalf("seed the cache: %v", err)
	}

	for range 50 {
		if _, err := store.Resolve(ctx, ref); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}

	if got := db.queries; got > 2 {
		t.Errorf("the durable store was queried %d times for 50 deliveries", got)
	}
}

// A durable store that is unreachable must not be recorded as "checked": concluding for
// the life of the process that a credential is safe when it may not be is the failure this
// whole change exists to prevent.
func TestAnUnreachableDurableStoreIsRetried(t *testing.T) {
	store, cache, db := tiered(t)
	ctx := context.Background()

	ref := NewReference("feed-credential")
	if err := cache.PutRef(ctx, ref, "feed-credential", "the-token"); err != nil {
		t.Fatalf("seed the cache: %v", err)
	}

	db.err = errors.New("clickhouse is unreachable")
	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("a delivery with a valid cached credential was refused: %v", err)
	}

	db.err = nil
	if _, err := store.Resolve(ctx, ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, stored := db.rows[ref]; !stored {
		t.Error("the credential was never backfilled after the store came back")
	}
}
