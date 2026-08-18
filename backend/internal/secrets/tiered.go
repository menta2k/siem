package secrets

import (
	"context"
	"errors"
	"sync"
)

// Reading from the cache, surviving on the durable copy.
//
// The shape is chosen by what actually failed. Every delivery resolves a credential, so
// the read path has to stay a Redis GET; and the cache is thrown away on any restart, so
// it cannot be the only copy. A miss therefore refills from the sealed copy instead of
// refusing — which is precisely the two-hour outage, healed automatically on the first
// delivery after a restart.

// CacheWriter is a store that can also be filled at a KNOWN reference.
//
// Put alone is not enough: refilling a cache has to reuse the reference the feeds table
// already points at, not mint a new one.
type CacheWriter interface {
	Store
	PutRef(ctx context.Context, ref, purpose, secret string) error
}

// Tiered reads through a cache and falls back to the durable copy.
type Tiered struct {
	cache   CacheWriter
	durable *DurableStore
	// backfilled remembers which references this process has already confirmed exist
	// durably, so the check below costs one query per credential per restart rather than
	// one per delivery.
	backfilled sync.Map
	// onRefill reports a cache miss that the durable copy answered. A miss is not an
	// error, but it is never routine either: it means the cache was emptied, and the
	// operator should learn that from a log rather than from a dark platform.
	onRefill func(ctx context.Context, ref string)
}

// NewTiered wires a cache in front of the durable store.
func NewTiered(
	cache CacheWriter, durable *DurableStore, onRefill func(context.Context, string),
) *Tiered {
	if onRefill == nil {
		onRefill = func(context.Context, string) {}
	}
	return &Tiered{cache: cache, durable: durable, onRefill: onRefill}
}

// ensureDurable writes a cached secret to the durable copy if it is not there yet.
//
// This is what MIGRATES a deployment that predates the durable copy. Its credentials
// exist only in the cache, and nothing would ever write them anywhere else — the next
// restart would lose them exactly as the last one did — so the first delivery that
// resolves each one backfills it. Once per reference per process, because after that the
// answer cannot change.
//
// Failure is deliberately silent to the caller: the delivery this is riding on has a
// valid credential and must be accepted either way.
func (t *Tiered) ensureDurable(ctx context.Context, ref, secret string) {
	if _, done := t.backfilled.LoadOrStore(ref, struct{}{}); done {
		return
	}

	if _, err := t.durable.Resolve(ctx, ref); err == nil {
		return
	} else if !errors.Is(err, ErrNotFound) {
		// The durable store is unreachable rather than missing the value. Forget the
		// mark so a later delivery tries again, instead of concluding for the lifetime
		// of the process that a credential is safe when it may not be.
		t.backfilled.Delete(ref)
		return
	}

	if err := t.durable.PutRef(ctx, ref, "feed-credential", secret); err != nil {
		t.backfilled.Delete(ref)
		return
	}
	t.onRefill(ctx, ref)
}

// Put writes the durable copy FIRST, then the cache.
//
// In that order because the failure modes are not symmetric: a durable write that lands
// without the cache costs one slow read, while a cached secret whose durable write failed
// is a credential that works until the next restart and then does not.
func (t *Tiered) Put(ctx context.Context, purpose, secret string) (string, error) {
	ref, err := t.durable.Put(ctx, purpose, secret)
	if err != nil {
		return "", err
	}
	// A cache write that fails is not fatal: the secret IS stored, and the next read
	// refills the cache from the durable copy. Ignored deliberately rather than returned,
	// because failing here would report a stored credential as unstored.
	_ = t.cache.PutRef(ctx, ref, purpose, secret)
	return ref, nil
}

// Resolve answers from the cache, refilling it from the durable copy on a miss.
func (t *Tiered) Resolve(ctx context.Context, ref string) (string, error) {
	secret, err := t.cache.Resolve(ctx, ref)
	if err == nil && secret != "" {
		t.ensureDurable(ctx, ref, secret)
		return secret, nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		// The cache is broken rather than empty. Fall through to the durable copy: a
		// degraded cache must not be able to stop ingestion either.
		t.onRefill(ctx, ref)
	}

	secret, durableErr := t.durable.Resolve(ctx, ref)
	if durableErr != nil {
		return "", durableErr
	}

	t.onRefill(ctx, ref)
	t.backfilled.Store(ref, struct{}{})
	// Best effort: a cache that refuses writes costs a slow read per delivery, which is
	// worth far less than refusing the delivery.
	_ = t.cache.PutRef(ctx, ref, "feed-credential", secret)
	return secret, nil
}

// Delete removes both copies, durable first for the reason Put gives.
func (t *Tiered) Delete(ctx context.Context, ref string) error {
	if err := t.durable.Delete(ctx, ref); err != nil {
		return err
	}
	return t.cache.Delete(ctx, ref)
}

// ErrNoDurableCopy reports that only the cache is configured.
//
// Returned as a value rather than an error from Build, because it is a state a deployment
// may legitimately be in and not a reason to refuse to start — but it is the exact state
// that took ingestion down for two hours, so nothing may treat it as normal or silent.
var ErrNoDurableCopy = errors.New(
	"secrets: no durable copy is configured, so a cache restart loses every feed " +
		"credential; set SECRETS_ENCRYPTION_KEY")

// Build assembles the secret store a service should use.
//
// With a key: the cache in front, the sealed copy behind it, self-healing on a miss.
// Without one: the cache alone, exactly as before, and ErrNoDurableCopy for the caller to
// log. A key that is present but MALFORMED is an error, because it means somebody
// intended durability and does not have it.
func Build(
	cache CacheWriter, db DB, encodedKey string, onRefill func(context.Context, string),
) (Store, error) {
	if encodedKey == "" {
		return cache, ErrNoDurableCopy
	}

	key, err := DecodeKey(encodedKey)
	if err != nil {
		return nil, err
	}
	sealer, err := NewSealer(key)
	if err != nil {
		return nil, err
	}
	durable, err := NewDurableStore(db, sealer)
	if err != nil {
		return nil, err
	}
	return NewTiered(cache, durable, onRefill), nil
}
