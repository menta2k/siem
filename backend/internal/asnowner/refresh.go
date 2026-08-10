package asnowner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
)

// DefaultSourceURL is the published combined table.
//
// iptoasn.com rebuilds it hourly from the RIR allocations and publishes it under PDDL
// v1.0, which is public domain — there is no attribution requirement and no per-query
// service to depend on, which is why this is a download rather than an API call.
const DefaultSourceURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// DefaultInterval is how often the table is refreshed.
//
// Daily, though upstream rebuilds hourly. AS ownership changes at the speed of registry
// paperwork, and the panel it feeds is read by humans: fetching 5 MB every hour to learn
// that AS8866 is still Vivacom would be pure cost.
const DefaultInterval = 24 * time.Hour

// DefaultTimeout bounds one download. Generous because the file is several megabytes
// over a link this platform does not control, and a refresh that takes a minute is
// harmless — it holds nothing and blocks nothing.
const DefaultTimeout = 2 * time.Minute

// Store is the persistence surface the refresh needs.
type Store interface {
	Replace(ctx context.Context, owners []chdata.ASNOwner, at time.Time) error
	Count(ctx context.Context) (uint64, error)
}

// Worker keeps the AS-owner table current.
//
// The ONLY component that reaches out to the public internet on a schedule. That is
// worth stating plainly: everything else here consumes what vendors send it. The
// exposure is bounded by refusing anything but HTTPS, capping both the compressed and
// decompressed size, and treating every failure as "keep what we have" — a stale name
// is worth far more than a pipeline that stops because a third-party host is down.
type Worker struct {
	store  Store
	client *http.Client
	log    mw.Logger

	source   string
	interval time.Duration
	now      func() time.Time
}

// Option adjusts a worker at construction.
type Option func(*Worker)

// WithHTTPClient replaces the client used for the download. Exists so a test can point
// the worker at an httptest TLS server, whose certificate no default client trusts —
// the alternative is a test that reaches the real internet, which is not a test.
func WithHTTPClient(client *http.Client) Option {
	return func(w *Worker) {
		if client != nil {
			w.client = client
		}
	}
}

// NewWorker constructs the refresh worker.
//
// An empty source or a non-positive interval falls back to the published defaults, so a
// deployment that sets neither still gets names.
func NewWorker(
	store Store, source string, interval time.Duration, log mw.Logger, opts ...Option,
) *Worker {
	if source == "" {
		source = DefaultSourceURL
	}
	if interval <= 0 {
		interval = DefaultInterval
	}

	worker := &Worker{
		store:    store,
		client:   &http.Client{Timeout: DefaultTimeout},
		log:      log,
		source:   source,
		interval: interval,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(worker)
	}
	return worker
}

// Source reports where the table is fetched from.
func (w *Worker) Source() string { return w.source }

// Interval reports how often it is refreshed.
func (w *Worker) Interval() time.Duration { return w.interval }

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "asn-owners" }

// Run refreshes the table until the context is cancelled.
//
// Deliberately NOT leader-elected, unlike retention. Every replica doing the same
// import writes identical rows into a ReplacingMergeTree keyed on the AS number, so the
// duplicates collapse on merge; taking a lock would add a failure mode to protect
// against an outcome that is already harmless.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Once at startup, so a fresh deployment has names on the first page load rather
	// than up to a day later. A failure here is logged, not fatal: the platform's job
	// is correlating events, and it must start without this.
	w.refreshLogging(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.refreshLogging(ctx)
		}
	}
}

func (w *Worker) refreshLogging(ctx context.Context) {
	count, err := w.Refresh(ctx)
	if err != nil {
		// Reported at WARN, not ERROR. The last good table is still being served, so
		// this degrades a label rather than breaking anything, and paging someone at
		// 3am because a public mirror was briefly unreachable is how alerts get muted.
		w.log.Warn(ctx, "asn owners: refresh failed, keeping the existing table",
			"error", err, "source", w.source)
		return
	}
	w.log.Info(ctx, "asn owners: table refreshed", "networks", count, "source", w.source)
}

// Refresh downloads the published table and replaces the stored snapshot.
func (w *Worker) Refresh(ctx context.Context) (int, error) {
	owners, err := w.download(ctx)
	if err != nil {
		return 0, err
	}
	if len(owners) == 0 {
		return 0, fmt.Errorf("%s yielded no networks", w.source)
	}

	rows := make([]chdata.ASNOwner, 0, len(owners))
	for _, owner := range owners {
		rows = append(rows, chdata.ASNOwner{
			ASN: owner.ASN, Name: owner.Name, Country: owner.Country,
		})
	}
	if err := w.store.Replace(ctx, rows, w.now()); err != nil {
		return 0, fmt.Errorf("store asn owners: %w", err)
	}
	return len(rows), nil
}

// download fetches and parses the source.
func (w *Worker) download(ctx context.Context) ([]Owner, error) {
	// HTTPS ONLY. The response becomes the names an analyst reads next to an ASN, and
	// over plain HTTP anyone on the path could choose them — mislabelling a hosting
	// network as a residential ISP is exactly the kind of quiet lie that misdirects an
	// investigation. The scheme is checked rather than assumed because the URL is
	// configurable.
	parsed, err := url.Parse(w.source)
	if err != nil {
		return nil, fmt.Errorf("parse asn source url: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("asn source must be https, got %q", parsed.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.source, nil)
	if err != nil {
		return nil, fmt.Errorf("build asn source request: %w", err)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", w.source, err)
	}
	defer func() {
		// Drained before closing so the connection can be reused rather than torn down,
		// bounded so a hostile body cannot make the drain itself the attack.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", w.source, resp.StatusCode)
	}

	return ParseGzip(resp.Body)
}
