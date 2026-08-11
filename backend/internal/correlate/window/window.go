// Package window holds the in-flight state of correlation windows.
//
// A correlation window is open while events for the same request may still arrive and
// closed once they may not. Two facts have to survive between events, and neither can
// live in worker memory: the workers are horizontally scaled and any of them may
// handle the next event for a window, and a restart must not lose a half-built record.
//
//	the MEMBERS of a window   — which events have been seen for a join key
//	the record IDENTITY       — the correlation_id the window was first emitted under
//
// Identity is stored, not recomputed, and that is the subtle part. A late arrival can
// change a window's join tier — two vendors turn out to share a request id after the
// record was already written on the heuristic key — and recomputing the id at that
// point would produce a SECOND row rather than amending the first. Since the schema
// has no way to supersede a row, the orphan would be permanent: two correlated
// records for one request, both reported as authoritative.
//
// # Lifetimes
//
// Every key expires after the correlation window plus the lateness bound, refreshed on
// each write. Nothing here is a store of record — ClickHouse is — so an expired window
// costs at most a missed amendment, never a lost event.
package window

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	fastjson "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
)

// DECODING USES goccy/go-json, ENCODING USES THE STANDARD LIBRARY, and the asymmetry is
// deliberate rather than an oversight.
//
// Decoding stored members was 13.2% of the processor's CPU samples even after the repeated
// work was cached away, and goccy parses this struct 3.4x faster than encoding/json (897ns
// against 3022ns, 7 allocations against 24). The wire format is identical, so a member
// written by the standard library reads back through goccy and vice versa -- which is what
// makes it safe to change one side and not the other, including during a rollout where both
// versions are running at once.
//
// It is scoped to THIS path on purpose. goccy leans heavily on unsafe, and the input here
// is bytes THIS PLATFORM WROTE to its own Redis -- not vendor payloads, which arrive from
// the internet and stay on the standard library's parser. A faster JSON library is worth a
// great deal less than a parser whose failure modes are understood by everyone reviewing
// the code that handles hostile input.

// ListEntry is one value appended to one list, with the TTL to refresh on that key.
type ListEntry struct {
	Key   string
	Value string
	TTL   time.Duration
}

// ScoreEntry is one member scored into one sorted set, with the TTL for that key.
type ScoreEntry struct {
	Key    string
	Member string
	Score  float64
	TTL    time.Duration
}

// Store is the subset of Redis this package needs.
type Store interface {
	RPush(ctx context.Context, key, value string, ttl time.Duration) (int64, error)
	// RPushMany applies many appends in one round trip. It exists because the
	// per-event round trip, not Redis, is what bounds correlation throughput.
	RPushMany(ctx context.Context, entries []ListEntry) error
	// ZAddMany applies many scored inserts in one round trip.
	ZAddMany(ctx context.Context, entries []ScoreEntry) error
	LRange(ctx context.Context, key string) ([]string, error)
	// LRangeMany reads many lists in one round trip. The closer's reads, not its
	// writes, are what a close pass spends its time on: see MembersMany.
	LRangeMany(ctx context.Context, keys []string) (map[string][]string, error)
	// LookupMany reads many keys at once, omitting those that are absent, for the
	// same reason Lookup treats absence as an ordinary answer.
	LookupMany(ctx context.Context, keys []string) (map[string]string, error)
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Get(ctx context.Context, key string) (string, error)
	// Lookup reads a key, reporting found=false when it is ABSENT rather than
	// returning an error.
	//
	// Get cannot serve this. Redis reports a missing key as an error, which is right
	// for callers that know the key exists — but the identity lookup asks about
	// identifiers that have usually never been claimed, so absence is its normal
	// result. Treating it as a failure took down every close pass and stopped
	// correlation outright.
	Lookup(ctx context.Context, key string) (string, bool, error)
	ZAdd(ctx context.Context, key, member string, score float64, ttl time.Duration) error
	ZPopDue(ctx context.Context, key string, max float64, limit int64) ([]string, error)
}

// Member is one event's contribution to a window, as persisted.
//
// It carries exactly the fields a correlated record is built from, and nothing else.
// The alternative — storing only event ids and re-reading the rows from ClickHouse
// when the window closes — would put one query per closed window on the hot path, and
// at 15k events/sec that is thousands of point lookups a second against a store built
// for scans. Storing the whole normalized event instead would drag the raw payload and
// the vendor-native extras through Redis for no benefit. This projection is roughly
// 200 bytes, so a full lateness bound of in-flight windows stays in the low hundreds
// of megabytes.
type Member struct {
	EventID   string    `json:"event_id"`
	Vendor    string    `json:"vendor"`
	EventTime time.Time `json:"event_time"`

	VendorRequestID string `json:"vendor_request_id,omitempty"`
	// LinkedRequestID is the second identifier this request is known by, carried so a
	// window that closes can follow it to partners filed under the other id.
	LinkedRequestID string `json:"linked_request_id,omitempty"`

	ClientIP       string `json:"client_ip,omitempty"`
	ClientIPShared bool   `json:"client_ip_shared,omitempty"`
	ClientASN      uint32 `json:"client_asn,omitempty"`
	ClientCountry  string `json:"client_country,omitempty"`

	RequestHost   string `json:"request_host,omitempty"`
	RequestPath   string `json:"request_path,omitempty"`
	RequestMethod string `json:"request_method,omitempty"`

	Verdict   string   `json:"verdict,omitempty"`
	RuleID    string   `json:"rule_id,omitempty"`
	RuleIDs   []string `json:"rule_ids,omitempty"`
	Score     *float32 `json:"score,omitempty"`
	ScoreKind string   `json:"score_kind,omitempty"`
}

// Scheduled is a window whose close deadline has passed.
type Scheduled struct {
	// Key is the join key the window formed on.
	Key string
	// TenantID scopes the window; the worker needs it before it can read anything.
	TenantID uuid.UUID
}

// DefaultBatch bounds how many closed windows one poll claims.
const DefaultBatch = 256

// Windows tracks open correlation windows.
//
// It holds no settings of its own. Correlation parameters are per-tenant and hot
// reloadable, so they arrive with each call: a tracker that captured them once at
// construction would keep a tenant's window state for the wrong length of time after
// an operator widened their lateness bound, silently truncating amendments.
type Windows struct {
	store Store
	// grace is the extra delay before a window is treated as closed, absorbing the
	// clock skew between vendors. Without it a window closes while a second vendor's
	// report of the same request is still in flight, and the join is lost.
	grace time.Duration
}

// DefaultGrace is how long a window waits past its end before closing.
//
// It has to outlast the SLOWEST vendor's delivery, and Cloudflare Logpush sets that.
// Measured over 90,909 events: p50 91s, p90 129s, p99 150s, max 178s. DataDome is
// derived from the same delivery so it tracks it exactly; F5 arrives in about 17s and
// nginx in 3.
//
// Two earlier values were set on a number that was never the right one. 34 seconds came
// from a single max(event_time) reading — which reports the FRESHEST row in the newest
// batch, the best case rather than the typical one — and produced first a 30s grace and
// then a 90s one. Ninety seconds landed almost exactly on Cloudflare's median, so
// whether its rows had arrived stayed close to a coin flip and roughly 50 records a
// minute were still being orphaned.
//
// Losing that coin costs more than a late amendment. F5 and nginx close alone and claim
// a correlation id under the origin fetch's ray, Cloudflare and DataDome close and claim
// a DIFFERENT id under the client-facing ray, and by the time the origin-fetch row
// reveals the two are one request both ids are published. Nothing was wrong at the
// moment either was claimed, so no lookup can reconcile them, and the schema cannot
// supersede a row — one record is orphaned for the whole retention period.
//
// 210 seconds clears the observed worst case of 178s with room for Logpush's batching
// on top, so a request is normally emitted once, complete, and never needs the
// amendment path at all.
//
// The cost is freshness, and it is substantial: a correlated record appears about three
// and a half minutes after the request. That is a deliberate trade. Most of the wait is
// Cloudflare's — its 91s median is the floor on any record involving it, whatever this
// constant says — and the Correlated page is for investigating what happened rather
// than watching traffic arrive. Search and the dashboards are unaffected; only
// correlated records wait.
const DefaultGrace = 210 * time.Second

// New builds a window tracker.
func New(store Store) *Windows {
	return &Windows{store: store, grace: DefaultGrace}
}

// TTL is how long window state outlives the window itself.
//
// It must cover the lateness bound: a record may still be amended right up to that
// deadline, and an amendment needs both the existing members and the stored identity.
func (w *Windows) TTL(settings keys.Settings) time.Duration {
	return normalizeSettings(settings).Total() + w.grace
}

// normalizeSettings substitutes platform defaults for unset values.
func normalizeSettings(settings keys.Settings) keys.Settings {
	defaults := keys.DefaultSettings()
	if settings.Window <= 0 {
		settings.Window = defaults.Window
	}
	if settings.LatenessBound <= 0 {
		settings.LatenessBound = defaults.LatenessBound
	}
	return settings
}

// Add records an event against a join key.
//
// Adding does NOT schedule the key for closing, and keeping the two apart is what
// stops a request being emitted twice. An event is filed under several keys — its
// exact identifier as well as its time window — but only ONE of them is the window
// that produces a record. Scheduling on every write would close the lookup buckets
// too, and each would emit its own copy of the same request: the first record would
// arrive already marked as an amendment of itself.
func (w *Windows) Add(
	ctx context.Context, tenantID uuid.UUID, key string, member Member, settings keys.Settings,
) error {
	encoded, err := json.Marshal(member)
	if err != nil {
		return fmt.Errorf("encode window member %s: %w", member.EventID, err)
	}

	_, err = w.store.RPush(ctx, membersKey(tenantID, key), string(encoded), w.TTL(settings))
	return err
}

// Members returns every event recorded against a join key.
//
// Duplicates are collapsed by event id. A redelivered event must not appear twice in
// a correlated record's event list, and it must not inflate the candidate count that
// drives the confidence score into reporting a false ambiguity.
func (w *Windows) Members(
	ctx context.Context, tenantID uuid.UUID, key string,
) ([]Member, error) {
	raw, err := w.store.LRange(ctx, membersKey(tenantID, key))
	if err != nil {
		return nil, err
	}
	return newDecodeCache().members(raw), nil
}

// MembersMany reads several windows in one round trip.
//
// A close pass reads a window per scheduled key and then a bucket per identifier while it
// chases exact partners, and asking for those one at a time is what a close pass actually
// spends its time on -- 34% of the processor's CPU samples were socket syscalls, with the
// process idle two thirds of the time. The decoding is unchanged and still per window: the
// saving is round trips, not work.
//
// Keys absent from Redis map to a nil slice, exactly as Members returns none for a window
// that has expired.
func (w *Windows) MembersMany(
	ctx context.Context, tenantID uuid.UUID, keys []string,
) (map[string][]Member, error) {
	out := make(map[string][]Member, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	// The Redis key is derived from the join key, so the mapping back has to be kept:
	// callers index by the join key they asked about, not by the storage key.
	redisKeys := make([]string, 0, len(keys))
	byRedisKey := make(map[string]string, len(keys))
	for _, key := range keys {
		redisKey := membersKey(tenantID, key)
		if _, duplicate := byRedisKey[redisKey]; duplicate {
			continue
		}
		byRedisKey[redisKey] = key
		redisKeys = append(redisKeys, redisKey)
	}

	raw, err := w.store.LRangeMany(ctx, redisKeys)
	if err != nil {
		return nil, err
	}

	// ONE DECODE PER DISTINCT ENTRY, not one per entry per key. The buckets read together
	// overlap heavily by construction: an event is filed under its window key AND under
	// every identifier it carries, and the partner walk reads a level's buckets together —
	// so a request's members appear in several of them at once. In production a tier-1
	// record spans 4.75 events contributing up to two identifiers each, which is roughly
	// nine buckets holding subsets of the same handful of members.
	//
	// Parsing one is ~3.2us; recognising one already parsed is a map lookup on its bytes.
	// This is the second-largest cost in the closer after the round trips it just stopped
	// paying, at 13.2% of the processor's CPU samples.
	cache := newDecodeCache()
	for redisKey, values := range raw {
		out[byRedisKey[redisKey]] = cache.members(values)
	}
	return out, nil
}

// decodeCache decodes each distinct stored entry once for the life of one batched read.
//
// Keyed by the STORED BYTES rather than by event id, which is what makes it safe: two
// entries that differ in any way decode separately, so a member can never be served a
// neighbour's contents. Identical bytes decode to identical members by definition.
type decodeCache struct {
	decoded map[string]Member
	corrupt map[string]struct{}
}

func newDecodeCache() *decodeCache {
	return &decodeCache{
		decoded: map[string]Member{},
		corrupt: map[string]struct{}{},
	}
}

// members turns one bucket's stored entries into members, collapsing duplicates by event
// id exactly as an unbatched read does.
func (c *decodeCache) members(raw []string) []Member {
	seen := make(map[string]bool, len(raw))
	members := make([]Member, 0, len(raw))

	for _, value := range raw {
		member, ok := c.decode(value)
		if !ok {
			continue
		}
		if seen[member.EventID] {
			continue
		}
		seen[member.EventID] = true
		members = append(members, member)
	}
	return members
}

// decode returns the member for one stored entry, reporting false for one that cannot be
// parsed.
//
// A corrupt entry is remembered as corrupt rather than retried per bucket, so a bad value
// costs one failed parse for the whole read instead of one per bucket it appears in. It is
// still SKIPPED rather than raised: the rest of the evidence is valid and a partial record
// beats no record.
func (c *decodeCache) decode(value string) (Member, bool) {
	if member, done := c.decoded[value]; done {
		return member, true
	}
	if _, bad := c.corrupt[value]; bad {
		return Member{}, false
	}

	var member Member
	if err := fastjson.Unmarshal([]byte(value), &member); err != nil {
		c.corrupt[value] = struct{}{}
		return Member{}, false
	}
	c.decoded[value] = member
	return member, true
}

// Identity returns the correlation id a window is emitted under, assigning proposed on
// first use and returning the previously assigned id on every later call.
//
// The assignment is atomic (SETNX) because two workers can close the same window
// concurrently; a read-then-write would let both believe they were first and emit the
// request under two different ids.
func (w *Windows) Identity(
	ctx context.Context, tenantID uuid.UUID, key string, proposed uuid.UUID,
	settings keys.Settings,
) (uuid.UUID, error) {
	redisKey := identityKey(tenantID, key)

	claimed, err := w.store.SetNX(ctx, redisKey, proposed.String(), w.TTL(settings))
	if err != nil {
		return uuid.Nil, err
	}
	if claimed {
		return proposed, nil
	}

	existing, err := w.store.Get(ctx, redisKey)
	if err != nil {
		return uuid.Nil, err
	}
	if existing == "" {
		// The key expired between the SETNX and the GET. Falling back to the proposed
		// id is right: the window is past its lateness bound, so nothing is amending
		// an older record any more.
		return proposed, nil
	}

	parsed, err := uuid.Parse(existing)
	if err != nil {
		return uuid.Nil, fmt.Errorf("stored correlation id %q for window %s: %w", existing, key, err)
	}
	return parsed, nil
}

// IdentityForAny resolves the correlation id a request is already known by, looking it
// up under EVERY identifier the request carries and claiming all of them.
//
// THE SPLIT-RECORD BUG THIS FIXES. A correlated record's id has to be derivable from
// any subset of its events, because the events arrive in any order. For a request
// through a Worker-protected edge no single identifier is present in every subset: F5
// and nginx only ever see the origin fetch's ray, DataDome is only reachable through
// the client-facing one, and just the Cloudflare origin-fetch row carries both.
//
// Computing the id from the group therefore cannot work, and computing it from the
// SMALLEST identifier — which is what the grouping does to stay deterministic — changes
// the answer as the group grows. In production that split 92.7% of f5+nginx records off
// into orphans: F5 and nginx arrive in real time and get a record keyed on their ray,
// Cloudflare arrives ~30 seconds later carrying the bridge, the canonical identifier
// flips to the parent, and the amendment lands on a NEW id instead of the existing one.
// One request, two records, and the older one is permanent because the schema has no
// way to supersede a row.
//
// So the id is REMEMBERED rather than recomputed. The first writer claims it under all
// the identifiers it knows, and a later group sharing any one of them finds it and
// amends the record that already exists.
//
// Claiming is SETNX throughout, so a concurrent closer cannot overwrite an id another
// worker has already published. Two workers that both find nothing can still race to
// claim different ids for disjoint identifier sets — the window is a single round trip
// wide, and the outcome is the split that happened before this existed, never worse.
func (w *Windows) IdentityForAny(
	ctx context.Context, tenantID uuid.UUID, identifiers []string, proposed uuid.UUID,
	settings keys.Settings,
) (uuid.UUID, error) {
	if len(identifiers) == 0 {
		return proposed, nil
	}

	resolved, err := w.existingIdentity(ctx, tenantID, identifiers)
	if err != nil {
		return uuid.Nil, err
	}
	if resolved == uuid.Nil {
		// Nothing claimed yet. The FIRST identifier is the authority — the caller sorts
		// them, so two workers seeing the same set contend on the same key and exactly
		// one wins.
		resolved, err = w.Identity(ctx, tenantID, identifiers[0], proposed, settings)
		if err != nil {
			return uuid.Nil, err
		}
	}

	// Publish under every identifier, so a later group arriving through any of them
	// finds this record rather than minting a second one. SETNX: an identifier already
	// pointing somewhere is left alone.
	for _, identifier := range identifiers {
		_, err := w.store.SetNX(
			ctx, identityKey(tenantID, identifier), resolved.String(), w.TTL(settings))
		if err != nil {
			return uuid.Nil, fmt.Errorf("claim identity for %s: %w", identifier, err)
		}
	}
	return resolved, nil
}

// existingIdentity returns the id already claimed under any identifier, or Nil.
//
// ONE ROUND TRIP FOR THE WHOLE SET, not one per identifier. The identifiers are read
// together and then scanned IN ORDER, which preserves the previous behaviour exactly: the
// first identifier holding a claim decides, so two closers seeing the same set still agree
// on the answer. Reading them in one go changes when the values arrive, not which one wins.
func (w *Windows) existingIdentity(
	ctx context.Context, tenantID uuid.UUID, identifiers []string,
) (uuid.UUID, error) {
	redisKeys := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		redisKeys = append(redisKeys, identityKey(tenantID, identifier))
	}

	claimed, err := w.store.LookupMany(ctx, redisKeys)
	if err != nil {
		return uuid.Nil, err
	}

	for i, identifier := range identifiers {
		existing := claimed[redisKeys[i]]
		if existing == "" {
			continue
		}
		parsed, err := uuid.Parse(existing)
		if err != nil {
			return uuid.Nil, fmt.Errorf(
				"stored correlation id %q for %s: %w", existing, identifier, err)
		}
		return parsed, nil
	}
	return uuid.Nil, nil
}

// Schedule marks a key as the window that will emit a record, due once its deadline
// passes. Calling it repeatedly for the same key simply moves the deadline out, which
// is exactly what a late arrival should do.
func (w *Windows) Schedule(
	ctx context.Context, tenantID uuid.UUID, key string, eventTime time.Time,
	settings keys.Settings,
) error {
	// Deadlines are measured from the EVENT time, not from now. Measuring from arrival
	// would let a backlogged feed keep pushing its windows into the future, so a replay
	// of yesterday's logs would never close anything.
	closesAt := eventTime.UTC().Add(normalizeSettings(settings).Window).Add(w.grace)
	return w.store.ZAdd(
		ctx, scheduleKey(), encodeScheduled(tenantID, key),
		float64(closesAt.UnixMilli()), w.TTL(settings),
	)
}

// Due claims windows whose close deadline has passed.
//
// Claiming removes them from the schedule, so each closed window is handed to exactly
// one worker. A window that receives a late arrival afterwards is simply rescheduled
// by Add, which is what turns the second pass into an amendment.
func (w *Windows) Due(ctx context.Context, now time.Time, limit int) ([]Scheduled, error) {
	if limit <= 0 {
		limit = DefaultBatch
	}

	values, err := w.store.ZPopDue(
		ctx, scheduleKey(), float64(now.UTC().UnixMilli()), int64(limit))
	if err != nil {
		return nil, err
	}

	out := make([]Scheduled, 0, len(values))
	for _, value := range values {
		scheduled, ok := decodeScheduled(value)
		if !ok {
			continue
		}
		out = append(out, scheduled)
	}
	return out, nil
}

func membersKey(tenantID uuid.UUID, key string) string {
	return fmt.Sprintf("correlate:members:%s:%s", tenantID, key)
}

func identityKey(tenantID uuid.UUID, key string) string {
	return fmt.Sprintf("correlate:id:%s:%s", tenantID, key)
}

func scheduleKey() string { return "correlate:schedule" }
