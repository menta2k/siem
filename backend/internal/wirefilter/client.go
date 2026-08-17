// Package wirefilter asks the local evaluator whether a Cloudflare rule expression would
// match a set of captured requests.
//
// The evaluator runs Cloudflare's OWN expression engine, so a verdict from it means what
// the same expression means in the dashboard. That is the entire reason it exists as a
// separate service rather than as a reimplementation here: an approximation of the
// expression language would be worse than nothing, because it would be believed.
package wirefilter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout bounds one evaluation.
//
// Generous for what the work is — parsing one expression and running it over at most a
// couple of hundred small requests — because the cost that matters is a cold container,
// not the evaluation.
const DefaultTimeout = 10 * time.Second

// maxResponseBytes bounds the reply. The evaluator answers with one verdict per request
// sent, so this is far above any real response.
const maxResponseBytes = 8 << 20

// Request is one captured request to evaluate against.
type Request struct {
	// ID is echoed back on the verdict. The caller's key, opaque to the evaluator.
	ID string `json:"id"`
	// Fields are the textual field values: path, method, host and so on.
	Fields map[string]string `json:"fields,omitempty"`
	// FieldsBase64 carries values that are not text — the request body above all, whose
	// bytes JSON would otherwise mangle.
	FieldsBase64 map[string]string `json:"fields_base64,omitempty"`
	// BodyTruncated says the captured body is a PREFIX of what the edge saw. F5 logs a
	// bounded slice of the request, so a body expression that misses may be missing on the
	// evidence rather than on the request.
	BodyTruncated bool `json:"body_truncated,omitempty"`
}

// SetBody attaches the request body, encoded so its bytes survive the trip.
func (r *Request) SetBody(body []byte, truncated bool) {
	if r.FieldsBase64 == nil {
		r.FieldsBase64 = map[string]string{}
	}
	r.FieldsBase64["http.request.body.raw"] = base64.StdEncoding.EncodeToString(body)
	r.BodyTruncated = truncated
}

// Outcome is one request's verdict.
type Outcome struct {
	ID      string `json:"id"`
	Matched bool   `json:"matched"`
	// Caveat is set when a NO cannot be trusted. Never set on a match.
	Caveat string `json:"caveat,omitempty"`
}

// Result is the evaluator's reply.
type Result struct {
	// Valid is false when the expression could not be parsed or names an unavailable
	// field. Outcomes is then empty — a broken expression has no verdict.
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
	// UnavailableFields names the fields the evaluator cannot fill from a stored request.
	UnavailableFields []string  `json:"unavailable_fields,omitempty"`
	Outcomes          []Outcome `json:"results,omitempty"`
}

// Client talks to the evaluator sidecar.
type Client struct {
	http *http.Client
	base string
}

// NewClient constructs a client for the evaluator at base.
func NewClient(base string) *Client {
	return &Client{http: &http.Client{Timeout: DefaultTimeout}, base: base}
}

// Configured reports whether an evaluator address was supplied at all.
//
// A deployment without one is normal: the evaluator is optional, and the migration pages
// work without it. The caller uses this to say so plainly rather than to fail a request
// that never had a chance of succeeding.
func (c *Client) Configured() bool { return c != nil && c.base != "" }

type evaluateBody struct {
	Expression string    `json:"expression"`
	Requests   []Request `json:"requests"`
}

// Evaluate runs one expression against the given requests.
//
// A REFUSED EXPRESSION IS NOT AN ERROR. The evaluator answers a parse failure with a
// 200 carrying valid=false, because "does this expression work" is the question being
// asked and "no, here is why" is the answer. Only a transport or decoding failure comes
// back as an error from here.
func (c *Client) Evaluate(
	ctx context.Context, expression string, requests []Request,
) (Result, error) {
	if !c.Configured() {
		return Result{}, fmt.Errorf("wirefilter: no evaluator configured")
	}

	body, err := json.Marshal(evaluateBody{Expression: expression, Requests: requests})
	if err != nil {
		return Result{}, fmt.Errorf("wirefilter: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.base+"/evaluate", bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("wirefilter: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("wirefilter: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Result{}, fmt.Errorf("wirefilter: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The evaluator's own message is not echoed to the caller: it describes a
		// malformed call, which is this package's fault and not the operator's.
		return Result{}, fmt.Errorf("wirefilter: evaluator returned %d", resp.StatusCode)
	}

	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		return Result{}, fmt.Errorf("wirefilter: decode response: %w", err)
	}
	return result, nil
}
