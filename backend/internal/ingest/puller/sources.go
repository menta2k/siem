package puller

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/menta2k/siem/internal/vendors"
)

// httpTimeout bounds a single vendor request. Generous, because an object can be
// tens of megabytes, but finite so one hung request cannot stall a feed forever.
const (
	httpTimeout  = 2 * time.Minute
	maxBodyBytes = 256 << 20
)

// SecretResolver turns a stored credential reference into the actual secret.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// credentialFor is set per-feed by the worker before a fetch. It is passed through
// the context rather than the Config so a credential can never be accidentally
// serialized into the stored pull configuration.
type credentialKey struct{}

// WithCredential attaches a resolved credential to a fetch context.
func WithCredential(ctx context.Context, credential string) context.Context {
	return context.WithValue(ctx, credentialKey{}, credential)
}

func credentialFrom(ctx context.Context) string {
	credential, _ := ctx.Value(credentialKey{}).(string)
	return credential
}

// ---------------------------------------------------------------- Cloudflare

// CloudflareSource reads Logpush output from an S3-compatible object store (R2 or S3).
//
// Objects are processed in lexicographic order because Logpush names them by time
// prefix, which makes the key itself a usable watermark. Objects are never deleted by
// the platform: the bucket is the customer's, and its lifecycle is theirs to manage.
type CloudflareSource struct {
	client *http.Client
}

// NewCloudflareSource constructs the source.
func NewCloudflareSource() *CloudflareSource {
	return &CloudflareSource{client: &http.Client{Timeout: httpTimeout}}
}

// Vendor returns the vendor name.
func (s *CloudflareSource) Vendor() string { return vendors.Cloudflare }

// listBucketResult is the subset of the S3 ListObjectsV2 response we need.
type listBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
	IsTruncated bool `xml:"IsTruncated"`
}

// Fetch lists objects after the watermark and downloads them in order.
func (s *CloudflareSource) Fetch(
	ctx context.Context, cfg Config, watermark string,
) ([]Batch, error) {
	keys, err := s.list(ctx, cfg, watermark)
	if err != nil {
		return nil, err
	}

	batches := make([]Batch, 0, len(keys))
	for _, key := range keys {
		payload, err := s.get(ctx, cfg, key)
		if err != nil {
			// Stop at this key rather than skipping ahead. The objects fetched so far
			// are returned for commit — their watermark lets the next poll resume at
			// exactly this key — and the error is reported alongside them.
			return batches, fmt.Errorf("fetch object %s: %w", key, err)
		}
		batches = append(batches, Batch{Payload: payload, Watermark: key, Label: key})
	}
	return batches, nil
}

// list returns object keys strictly after the watermark, in order.
func (s *CloudflareSource) list(
	ctx context.Context, cfg Config, watermark string,
) ([]string, error) {
	endpoint, err := url.Parse(strings.TrimSuffix(cfg.Endpoint, "/") + "/" + cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("parse object store endpoint: %w", err)
	}

	query := endpoint.Query()
	query.Set("list-type", "2")
	if cfg.Prefix != "" {
		query.Set("prefix", cfg.Prefix)
	}
	// start-after is what makes the fetch resumable: the store returns only keys
	// sorted after the last one we committed.
	if watermark != "" {
		query.Set("start-after", watermark)
	}
	endpoint.RawQuery = query.Encode()

	body, err := s.do(ctx, http.MethodGet, endpoint.String())
	if err != nil {
		return nil, err
	}

	var result listBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse object listing: %w", err)
	}

	keys := make([]string, 0, len(result.Contents))
	for _, object := range result.Contents {
		// Zero-length objects are Logpush's directory markers, not data.
		if object.Size > 0 {
			keys = append(keys, object.Key)
		}
	}
	// The store is expected to return sorted keys, but sorting locally makes the
	// watermark's correctness independent of that promise.
	sort.Strings(keys)
	return keys, nil
}

func (s *CloudflareSource) get(ctx context.Context, cfg Config, key string) ([]byte, error) {
	objectURL := strings.TrimSuffix(cfg.Endpoint, "/") + "/" + cfg.Bucket + "/" + key
	return s.do(ctx, http.MethodGet, objectURL)
}

func (s *CloudflareSource) do(ctx context.Context, method, rawURL string) ([]byte, error) {
	return doRequest(ctx, s.client, method, rawURL, nil)
}

// ---------------------------------------------------------------- F5

// F5Source reads security events from the F5 Distributed Cloud API.
//
// The API is cursor-paged, so the cursor is the watermark directly.
type F5Source struct {
	client *http.Client
}

// NewF5Source constructs the source.
func NewF5Source() *F5Source {
	return &F5Source{client: &http.Client{Timeout: httpTimeout}}
}

// Vendor returns the vendor name.
func (s *F5Source) Vendor() string { return vendors.F5 }

type f5Response struct {
	Events []json.RawMessage `json:"events"`
	// NextCursor is empty when the caller has caught up.
	NextCursor string `json:"next_cursor"`
}

// Fetch pages forward from the cursor.
func (s *F5Source) Fetch(ctx context.Context, cfg Config, watermark string) ([]Batch, error) {
	endpoint, err := url.Parse(strings.TrimSuffix(cfg.Endpoint, "/") + "/api/data/namespaces/" +
		cfg.Namespace + "/app_security/events")
	if err != nil {
		return nil, fmt.Errorf("parse f5 endpoint: %w", err)
	}

	var batches []Batch
	cursor := watermark

	for range cfg.MaxBatches() {
		query := endpoint.Query()
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		endpoint.RawQuery = query.Encode()

		body, err := doRequest(ctx, s.client, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			// Both: the pages fetched so far are committable, and the failure is
			// still reported so the operator sees the vendor outage.
			return batches, fmt.Errorf("fetch f5 page: %w", err)
		}

		var page f5Response
		if err := json.Unmarshal(body, &page); err != nil {
			return batches, fmt.Errorf("parse f5 page: %w", err)
		}
		if len(page.Events) == 0 {
			break
		}

		payload, err := json.Marshal(page.Events)
		if err != nil {
			return batches, fmt.Errorf("re-encode f5 events: %w", err)
		}
		batches = append(batches, Batch{
			Payload:   payload,
			Watermark: page.NextCursor,
			Label:     fmt.Sprintf("cursor=%s", truncate(page.NextCursor, 24)),
		})

		if page.NextCursor == "" || page.NextCursor == cursor {
			// No further pages, or the vendor returned the same cursor — stopping
			// avoids an infinite loop on a misbehaving API.
			break
		}
		cursor = page.NextCursor
	}

	return batches, nil
}

// ---------------------------------------------------------------- DataDome

// DataDomeSource reads from the DataDome log export API.
//
// The API is paged by time range, so the watermark is an RFC3339 timestamp: the end
// of the last range successfully committed.
type DataDomeSource struct {
	client *http.Client
	now    func() time.Time
}

// NewDataDomeSource constructs the source.
func NewDataDomeSource() *DataDomeSource {
	return &DataDomeSource{client: &http.Client{Timeout: httpTimeout}, now: time.Now}
}

// Vendor returns the vendor name.
func (s *DataDomeSource) Vendor() string { return vendors.DataDome }

// exportWindow is how much time one request covers. Small enough that a single
// response stays a manageable size at high traffic.
const exportWindow = 5 * time.Minute

// exportLag is how far behind now a window may end.
//
// Vendors do not make an event queryable the instant it happens. Fetching right up to
// now would return a partially-filled window and then advance the watermark past it,
// permanently missing the events that arrived a moment later.
const exportLag = 2 * time.Minute

// Fetch requests successive time windows from the watermark.
func (s *DataDomeSource) Fetch(ctx context.Context, cfg Config, watermark string) ([]Batch, error) {
	from, err := parseWatermarkTime(watermark, s.now())
	if err != nil {
		return nil, err
	}

	ceiling := s.now().UTC().Add(-exportLag)
	var batches []Batch

	for range cfg.MaxBatches() {
		to := from.Add(exportWindow)
		if to.After(ceiling) {
			break
		}

		endpoint, err := url.Parse(strings.TrimSuffix(cfg.Endpoint, "/") + "/v1/logs/export")
		if err != nil {
			return batches, fmt.Errorf("parse datadome endpoint: %w", err)
		}
		query := endpoint.Query()
		query.Set("from", from.Format(time.RFC3339))
		query.Set("to", to.Format(time.RFC3339))
		endpoint.RawQuery = query.Encode()

		body, err := doRequest(ctx, s.client, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return batches, fmt.Errorf("fetch datadome window %s: %w",
				from.Format(time.RFC3339), err)
		}

		if len(body) > 0 {
			batches = append(batches, Batch{
				Payload:   body,
				Watermark: to.Format(time.RFC3339),
				Label:     fmt.Sprintf("%s..%s", from.Format(time.RFC3339), to.Format(time.RFC3339)),
			})
		}
		from = to
	}

	return batches, nil
}

// parseWatermarkTime resolves the starting point for a time-ranged fetch.
func parseWatermarkTime(watermark string, now time.Time) (time.Time, error) {
	if watermark == "" {
		// A new feed starts one hour back rather than at the epoch: fetching all
		// history on first poll would hammer the vendor and flood the pipeline.
		return now.UTC().Add(-time.Hour).Truncate(time.Minute), nil
	}

	parsed, err := time.Parse(time.RFC3339, watermark)
	if err != nil {
		return time.Time{}, fmt.Errorf("watermark %q is not an RFC3339 time: %w", watermark, err)
	}
	return parsed.UTC(), nil
}

// ---------------------------------------------------------------- shared

func doRequest(
	ctx context.Context, client *http.Client, method, rawURL string, body io.Reader,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if credential := credentialFrom(ctx); credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	req.Header.Set("Accept", "application/json, application/x-ndjson, */*")

	resp, err := client.Do(req)
	if err != nil {
		// The URL is included but never the credential.
		return nil, fmt.Errorf("request %s: %w", redactURL(rawURL), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request %s returned %d", redactURL(rawURL), resp.StatusCode)
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", redactURL(rawURL), err)
	}
	return payload, nil
}

// redactURL strips the query string before a URL reaches a log.
//
// Some vendors accept a token as a query parameter, and an error message is exactly
// the place a credential ends up copied into a ticket.
func redactURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[unparseable url]"
	}
	parsed.RawQuery = ""
	parsed.User = nil
	return parsed.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
