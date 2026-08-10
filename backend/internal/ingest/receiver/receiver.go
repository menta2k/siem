// Package receiver serves the vendor-facing ingest endpoints.
//
// The response contract is the important part of this package:
//
//	202 — every event durably committed
//	207 — committed, some events dead-lettered with per-event reasons
//	429 — quota exceeded, with Retry-After
//	503 — the broker could not confirm the write
//
// A 2xx is returned ONLY after the broker acknowledges. Any doubt produces a
// retryable status, because a vendor retry is absorbed by deduplication while a false
// acknowledgement loses the event permanently (Constitution Principle II).
package receiver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	"github.com/menta2k/siem/internal/ingest/filter"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
)

// FeedStore resolves and authenticates feeds.
type FeedStore interface {
	GetForIngest(ctx context.Context, feedID uuid.UUID) (chdata.Feed, error)
}

// SecretResolver turns a stored credential reference into the actual secret.
//
// Feed credentials are stored by reference, never inline, so this is the only place
// a vendor secret exists in memory and only for the duration of one comparison.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// HealthRecorder accumulates per-feed health counters (FR-008).
//
// The sample type lives in the ingest package so the receiver and the aggregator
// cannot drift apart into two shapes that look interchangeable but are not.
type HealthRecorder interface {
	Record(ctx context.Context, sample ingest.HealthSample)
}

// Options configures the receiver.
type Options struct {
	MaxBodyBytes   int64
	MaxBatchEvents int
	// CommitTimeout bounds the detached durable commit — the phase that deliberately
	// outlives the client connection. It is the platform's OWN patience, not the
	// sender's: a vendor that disconnects early must not shorten it, and a broker that
	// never answers must not hold a goroutine forever.
	//
	// Generous, because the batches that need it most are the largest. A backlogged
	// Logpush job delivers tens of thousands of events at once, and refusing those is
	// what leaves a backlog undrainable.
	CommitTimeout time.Duration
}

// DefaultCommitTimeout applies when Options leaves it unset.
const DefaultCommitTimeout = 2 * time.Minute

// Receiver handles vendor deliveries.
type Receiver struct {
	feeds     FeedStore
	secrets   SecretResolver
	registry  *vendors.Registry
	publisher *ingest.Publisher
	deduper   *dedup.Deduper
	quotas    *ingest.QuotaEnforcer
	filters   *filter.Cache
	health    HealthRecorder
	log       mw.Logger
	opts      Options
}

// New constructs a receiver.
func New(
	feeds FeedStore, secrets SecretResolver, registry *vendors.Registry,
	publisher *ingest.Publisher, deduper *dedup.Deduper, quotas *ingest.QuotaEnforcer,
	filters *filter.Cache, health HealthRecorder, log mw.Logger, opts Options,
) *Receiver {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 32 << 20
	}
	if opts.MaxBatchEvents <= 0 {
		opts.MaxBatchEvents = 50000
	}
	return &Receiver{
		feeds: feeds, secrets: secrets, registry: registry, publisher: publisher,
		deduper: deduper, quotas: quotas, filters: filters,
		health: health, log: log, opts: opts,
	}
}

// Handler routes deliveries to /ingest/v1/{vendor}/{feed_id}.
//
// PUT is accepted alongside POST because Cloudflare Logpush VALIDATES a destination
// before it will save the job, and that validation reuses its object-store upload path
// — a PUT, not the POST it uses for actual log delivery. Go's ServeMux answers a
// registered path with an unregistered method as 405, so a POST-only route makes
// Logpush fail with `error writing object: error uploading to https: status:405` and
// the job cannot be created at all.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest/v1/{vendor}/{feed_id}", r.handleDelivery)
	mux.HandleFunc("PUT /ingest/v1/{vendor}/{feed_id}", r.handleDelivery)
	return mux
}

func (r *Receiver) handleDelivery(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	receivedAt := time.Now().UTC()

	vendorName := strings.ToLower(req.PathValue("vendor"))
	feedID, err := uuid.Parse(req.PathValue("feed_id"))
	if err != nil {
		writeError(w, mw.ValidationFailed("the feed id is not a valid identifier"))
		return
	}

	feed, adapter, err := r.resolveFeed(ctx, vendorName, feedID)
	if err != nil {
		writeError(w, mw.AsError(err))
		return
	}

	body, err := r.readBody(req)
	if err != nil {
		// A REFUSED DELIVERY MUST BE VISIBLE HERE, not only in the vendor's console.
		// An oversized batch is answered 413 and dropped, and the sender retries the
		// same bytes forever — so if the platform says nothing, an operator watching
		// our logs sees a healthy service while the vendor sees a wall. That is exactly
		// how a backlog went undiagnosed: our side was silent, Cloudflare reported the
		// error, and only the vendor knew.
		//
		// ContentLength is logged rather than the bytes read, because the reader stops
		// AT the limit and cannot say how far over the batch actually was. It is what
		// an operator needs to size the limit correctly.
		if mw.AsError(err).Code == mw.CodePayloadTooLarge {
			r.log.Warn(ctx, "delivery refused as too large",
				"feed_id", feed.ID.String(), "vendor", feed.Vendor,
				"content_length", req.ContentLength, "limit_bytes", r.opts.MaxBodyBytes)
		}
		writeError(w, mw.AsError(err))
		return
	}

	if err := r.authenticate(ctx, req, feed, body); err != nil {
		// A failed authentication is health-relevant: it is how an expired credential
		// surfaces to the operator rather than as silent traffic loss.
		r.health.Record(ctx, ingest.HealthSample{
			TenantID: feed.TenantID, FeedID: feed.ID, CredentialValid: false,
		})
		writeError(w, mw.AsError(err))
		return
	}

	// Answered AFTER authentication, so a probe still has to present the feed's
	// credential — this confirms the endpoint and the token together, which is the
	// whole point of the vendor validating a destination.
	if isDestinationProbe(body) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	// FROM HERE THE WORK OUTLIVES THE CLIENT.
	//
	// Everything above legitimately belongs to the request: if the sender hangs up
	// while we are reading its body or checking its credential, there is nothing worth
	// finishing. The durable commit is the opposite. The body is already in hand, and
	// abandoning it half-published helps nobody — the sender will deliver the same batch
	// again, and we will abandon that one too.
	//
	// That is not hypothetical. Cloudflare Logpush gives up on a slow destination and
	// disconnects, which cancelled the request context mid-publish and rolled the whole
	// batch back. Every retry carried the same batch, took the same time, and was
	// cancelled at the same point: 36,000-event batches never landed, and a two-hour
	// backlog sat still for hours because its largest batches could never succeed.
	//
	// Detached, the commit completes even when nobody is listening for the answer. The
	// sender's retry then finds the events already ingested and is suppressed by dedup,
	// so the batch costs one commit rather than an unbounded loop of them.
	r.commitDelivery(ctx, w, feed, adapter, body, receivedAt)
}

// commitDelivery runs the durable commit and answers the sender.
func (r *Receiver) commitDelivery(
	ctx context.Context, w http.ResponseWriter, feed chdata.Feed,
	adapter vendors.Adapter, body []byte, receivedAt time.Time,
) {
	commitCtx, cancelCommit := context.WithTimeout(
		context.WithoutCancel(ctx), r.commitTimeout())
	defer cancelCommit()

	outcome, err := r.accept(commitCtx, feed, adapter, body, receivedAt)
	if err != nil {
		r.observeFailure(feed, err)
		writeError(w, mw.AsError(err))
		return
	}
	ingest.ObserveDelivery(feed.Vendor, feed.ID.String(), outcome,
		int64(len(body)), time.Since(receivedAt))

	status := http.StatusAccepted
	if outcome.HasRejections() {
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, outcome)
}

// commitTimeout is the configured bound, or the default when unset.
func (r *Receiver) commitTimeout() time.Duration {
	if r.opts.CommitTimeout > 0 {
		return r.opts.CommitTimeout
	}
	return DefaultCommitTimeout
}

// observeFailure records a refused delivery against the right metric, so an operator
// can tell a broker outage from a customer exceeding their quota.
func (r *Receiver) observeFailure(feed chdata.Feed, err error) {
	switch mw.AsError(err).Code {
	case mw.CodeBrokerUnavailable:
		ingest.ObservePublishFailure(feed.Vendor, feed.ID.String())
	case mw.CodeRateLimited:
		ingest.ObserveQuotaRejection(feed.Vendor, feed.ID.String())
	}
}

// resolveFeed loads the feed and its adapter, rejecting a vendor/feed mismatch.
func (r *Receiver) resolveFeed(
	ctx context.Context, vendorName string, feedID uuid.UUID,
) (chdata.Feed, vendors.Adapter, error) {
	adapter, err := r.registry.Get(vendorName)
	if err != nil {
		return chdata.Feed{}, nil, mw.NotFound("vendor").WithCause(err)
	}

	feed, err := r.feeds.GetForIngest(ctx, feedID)
	if err != nil {
		if errors.Is(err, chdata.ErrNotFound) {
			return chdata.Feed{}, nil, mw.NotFound("feed")
		}
		return chdata.Feed{}, nil, mw.Internal().WithCause(err)
	}

	// A token valid for one feed must not deliver to another vendor's endpoint.
	if feed.Vendor != vendorName {
		return chdata.Feed{}, nil, mw.FeedTokenMismatch()
	}
	if !feed.Enabled {
		return chdata.Feed{}, nil, mw.NotFound("feed")
	}
	return feed, adapter, nil
}

// readBody reads the delivery under a hard size cap.
func (r *Receiver) readBody(req *http.Request) ([]byte, error) {
	limited := http.MaxBytesReader(nil, req.Body, r.opts.MaxBodyBytes)
	defer func() { _ = req.Body.Close() }()

	body, err := io.ReadAll(limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, mw.PayloadTooLarge(r.opts.MaxBodyBytes)
		}
		return nil, mw.ValidationFailed("the request body could not be read").WithCause(err)
	}
	if len(body) == 0 {
		return nil, mw.ValidationFailed("the request body is empty")
	}
	return body, nil
}

// authenticate verifies the bearer token and, where configured, the body signature.
//
// A valid token alone is NOT sufficient when signing is configured: the signature is
// what proves the body was not altered in transit.
func (r *Receiver) authenticate(
	ctx context.Context, req *http.Request, feed chdata.Feed, body []byte,
) error {
	token, ok := credentialFrom(req)
	if !ok {
		return mw.FeedCredentialInvalid()
	}

	expected, err := r.secrets.Resolve(ctx, feed.CredentialRef)
	if err != nil {
		return mw.Internal().WithCause(err)
	}
	// Constant time: a byte-by-byte comparison leaks how much of the token matched.
	if subtleCompare(token, expected) != 1 {
		return mw.FeedCredentialInvalid()
	}

	if feed.SigningSecretRef == "" {
		return nil
	}

	signature := req.Header.Get("X-Signature")
	if signature == "" {
		return mw.FeedCredentialInvalid()
	}
	secret, err := r.secrets.Resolve(ctx, feed.SigningSecretRef)
	if err != nil {
		return mw.Internal().WithCause(err)
	}
	if !validSignature(body, secret, signature) {
		return mw.FeedCredentialInvalid()
	}
	return nil
}

// credentialFrom reads the feed credential, preferring the Authorization header.
//
// The query parameter exists because some vendors' webhook configuration has NO field
// for a custom header — DataDome's is one: it offers a name, a URL, a payload format and
// severity filters, and nothing else. Without this those vendors cannot authenticate at
// all, which is a worse outcome than a credential in a query string.
//
// It is a fallback, never the recommendation. A query string is visible to every proxy
// and reverse proxy on the path and is written to their access logs by default, so a
// token sent this way should be treated as more exposed than one in a header and rotated
// more readily. The header is checked first so a vendor that supports both never
// downgrades itself.
func credentialFrom(req *http.Request) (string, bool) {
	if token, ok := bearerToken(req.Header.Get("Authorization")); ok {
		return token, true
	}
	if token := req.URL.Query().Get("token"); token != "" {
		return token, true
	}
	return "", false
}

// accept parses, deduplicates, quota-checks, and durably commits a delivery.
func (r *Receiver) accept(
	ctx context.Context, feed chdata.Feed, adapter vendors.Adapter,
	body []byte, receivedAt time.Time,
) (ingest.Outcome, error) {
	format, recognized := adapter.Detect(body)
	if !recognized {
		return ingest.Outcome{}, mw.ValidationFailed("the payload format was not recognized")
	}

	records, err := adapter.Parse(body, format)
	if err != nil {
		// The batch envelope itself is unreadable, so nothing can be committed. This
		// is a 400: retrying the same bytes will fail identically.
		return ingest.Outcome{}, mw.ValidationFailed("the batch could not be parsed").WithCause(err)
	}
	if len(records) > r.opts.MaxBatchEvents {
		return ingest.Outcome{}, mw.PayloadTooLarge(int64(r.opts.MaxBatchEvents))
	}

	if err := r.checkQuota(ctx, feed, len(records), int64(len(body))); err != nil {
		return ingest.Outcome{}, err
	}

	batchID := normalize.BatchID()
	envelopes, rejections, filtered := ingest.BuildEnvelopes(adapter, records, ingest.EnvelopeMeta{
		TenantID: feed.TenantID, FeedID: feed.ID, BatchID: batchID, ReceivedAt: receivedAt,
		IdentityFor: func(vendor, vendorRequestID string, raw []byte) string {
			return normalize.EventIDFor(feed.ID, vendor, vendorRequestID, raw)
		},
		Filters: r.filters.For(ctx, feed.TenantID),
	})

	accepted, duplicates := r.partition(ctx, feed, envelopes, rejections)

	if err := r.commit(ctx, feed, envelopes, accepted, rejections); err != nil {
		// Nothing is marked as seen: the events were NOT committed, so a vendor retry
		// must be able to deliver them again.
		return ingest.Outcome{}, err
	}

	r.markCommitted(ctx, feed, accepted)

	return r.report(ctx, feed, delivery{
		batchID: batchID, accepted: len(accepted), rejections: rejections,
		duplicates: duplicates, filtered: filtered, bytes: int64(len(body)),
	}), nil
}

// commit is the durability boundary. A failure here MUST surface as a retryable
// error — never as a 2xx the system cannot honour.
func (r *Receiver) commit(
	ctx context.Context, feed chdata.Feed,
	envelopes, accepted []ingest.Envelope, rejections []ingest.Rejection,
) error {
	if err := r.publisher.PublishBatch(ctx, accepted); err != nil {
		r.log.Error(ctx, "durable commit failed",
			"feed_id", feed.ID.String(), "cause", err.Error())
		return mw.BrokerUnavailable().WithCause(err)
	}

	// Dead-lettering happens AFTER the commit and must not fail the request: the
	// accepted events are already durable, and the rejections are counted regardless.
	if err := r.publisher.PublishRejections(ctx, envelopes, rejections); err != nil {
		r.log.Error(ctx, "dead-letter publish failed",
			"feed_id", feed.ID.String(), "cause", err.Error())
	}
	return nil
}

// checkQuota charges the delivery against the feed's volume limits.
//
// It fails OPEN on a counter error: losing a customer's logs because Redis is
// unavailable would be far worse than briefly over-accepting. The degradation is
// logged rather than passing silently.
func (r *Receiver) checkQuota(
	ctx context.Context, feed chdata.Feed, eventCount int, byteCount int64,
) error {
	decision, err := r.quotas.Check(ctx, feed.ID.String(), eventCount, byteCount,
		feed.QuotaEventsPerSec, feed.QuotaBytesPerDay)
	if err != nil {
		r.log.Warn(ctx, "quota check unavailable, allowing delivery", "cause", err.Error())
	}
	if !decision.Allowed {
		return quotaError(decision)
	}
	return nil
}

// partition removes rejected and already-seen events, returning what to commit.
func (r *Receiver) partition(
	ctx context.Context, feed chdata.Feed, envelopes []ingest.Envelope, rejections []ingest.Rejection,
) (accepted []ingest.Envelope, duplicates int) {
	rejected := make(map[int]bool, len(rejections))
	for _, rejection := range rejections {
		rejected[rejection.Index] = true
	}

	candidates := make([]ingest.Envelope, 0, len(envelopes))
	eventIDs := make([]string, 0, len(envelopes))
	for i, envelope := range envelopes {
		if rejected[i] {
			continue
		}
		candidates = append(candidates, envelope)
		eventIDs = append(eventIDs, envelope.EventID)
	}

	// Read-only. Nothing is recorded until the commit succeeds.
	result, err := r.deduper.Filter(ctx, feed.TenantID.String(), eventIDs)
	if err != nil {
		// Fails open: everything is treated as fresh, and the degradation is logged.
		r.log.Warn(ctx, "dedup unavailable, accepting all events", "cause", err.Error())
	}

	accepted = make([]ingest.Envelope, 0, len(result.Fresh))
	for _, idx := range result.Fresh {
		if idx >= 0 && idx < len(candidates) {
			accepted = append(accepted, candidates[idx])
		}
	}
	return accepted, result.Duplicates
}

// markCommitted records the accepted events as seen.
//
// This runs ONLY after a confirmed durable commit. Marking during filtering would
// suppress the vendor's retry after a 503 and lose the event permanently.
func (r *Receiver) markCommitted(
	ctx context.Context, feed chdata.Feed, accepted []ingest.Envelope,
) {
	if err := r.deduper.Mark(ctx, feed.TenantID.String(), eventIDsOf(accepted)); err != nil {
		// Not fatal: the events are already durable. A lost marker only means a later
		// redelivery is re-published and collapsed by the storage layer.
		r.log.Warn(ctx, "could not record dedup markers", "cause", err.Error())
	}
}

// eventIDsOf extracts the ids of committed envelopes for dedup marking.
func eventIDsOf(envelopes []ingest.Envelope) []string {
	ids := make([]string, 0, len(envelopes))
	for _, envelope := range envelopes {
		ids = append(ids, envelope.EventID)
	}
	return ids
}

func quotaError(decision ingest.QuotaDecision) error {
	err := mw.RateLimited()
	return err.WithCause(errors.New(decision.Reason))
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}

// validSignature checks an HMAC-SHA256 signature over the raw body.
func validSignature(body []byte, secret, provided string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(strings.TrimPrefix(provided, "sha256=")))
}

// subtleCompare is a constant-time string comparison returning 1 on equality.
func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		// Length alone is not secret, and comparing unequal lengths would leak
		// through the loop bound anyway.
		return 0
	}
	var diff byte
	for i := range len(a) {
		diff |= a[i] ^ b[i]
	}
	if diff == 0 {
		return 1
	}
	return 0
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, err *mw.Error) {
	if retryAfter := retryAfterFor(err); retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	writeJSON(w, err.HTTPStatus(), err)
}

// retryAfterFor supplies a backoff hint for the statuses a vendor should retry.
func retryAfterFor(err *mw.Error) int {
	switch err.Code {
	case mw.CodeRateLimited:
		return 1
	case mw.CodeBrokerUnavailable:
		return 5
	default:
		return 0
	}
}

// delivery is the tally of one accepted batch, kept together so the health sample and the
// response cannot disagree about what happened to it.
type delivery struct {
	batchID    uuid.UUID
	accepted   int
	rejections []ingest.Rejection
	duplicates int
	filtered   int
	bytes      int64
}

// report records feed health and returns what the sender is told.
//
// Filtered events are counted in BOTH. A filtered event is stored nowhere at all, so
// without these two numbers neither an operator nor the sending vendor can tell "excluded
// on purpose" from "silently lost".
func (r *Receiver) report(
	ctx context.Context, feed chdata.Feed, d delivery,
) ingest.Outcome {
	r.health.Record(ctx, ingest.HealthSample{
		TenantID: feed.TenantID, FeedID: feed.ID,
		EventsReceived: d.accepted, EventsRejected: len(d.rejections),
		EventsFiltered:       d.filtered,
		DuplicatesSuppressed: d.duplicates, BytesReceived: d.bytes,
		CredentialValid: true,
	})

	return ingest.Outcome{
		BatchID:              d.batchID,
		Accepted:             d.accepted,
		DuplicatesSuppressed: d.duplicates,
		Filtered:             d.filtered,
		Rejected:             d.rejections,
	}
}
