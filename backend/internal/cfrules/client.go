// Package cfrules resolves a Cloudflare rule id to the rule's name.
//
// Logpush reports the rule that matched as an opaque identifier and nothing else, so a
// blocked request in the console says only that "a rule" fired — which the verdict
// already said. The names live in Cloudflare's ruleset API, behind the customer's own
// token, and this package fetches them, stores them, and puts them in front of the
// analyst next to the id.
package cfrules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAPIBase is Cloudflare's v4 API.
const DefaultAPIBase = "https://api.cloudflare.com/client/v4"

// DefaultTimeout bounds one API call. Generous, because a zone with many managed
// rulesets needs several round trips and none of them holds anything.
const DefaultTimeout = 30 * time.Second

// maxResponseBytes bounds a single response body.
//
// The largest thing fetched here is one managed ruleset's rules, a few hundred kilobytes.
// The cap exists because this is a network boundary, not because the real payload is
// close to it.
const maxResponseBytes = 32 << 20

// Zone is a Cloudflare zone the token can see.
type Zone struct {
	ID   string
	Name string
}

// Ruleset is one ruleset on a zone.
type Ruleset struct {
	ID   string
	Name string
	Kind string
	// Phase names when the ruleset runs, which is what distinguishes a WAF ruleset from
	// a rate-limiting or transform one.
	Phase string
}

// Rule is one rule with the name an analyst needs.
type Rule struct {
	ID          string
	Description string
	Action      string
	// Ref and Categories are present on managed rules only. A custom rule has whatever
	// the customer typed and nothing else.
	Ref        string
	Categories []string
}

// Client reads zones and rulesets from Cloudflare's API.
type Client struct {
	http  *http.Client
	base  string
	token string
}

// NewClient constructs a client for one tenant's token.
func NewClient(token, base string) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	return &Client{
		http:  &http.Client{Timeout: DefaultTimeout},
		base:  strings.TrimRight(base, "/"),
		token: token,
	}
}

// envelope is Cloudflare's standard response wrapper.
//
// Errors are reported INSIDE a 200 as often as by status code, so a client that checks
// only the status silently treats a permission failure as an empty ruleset — and the
// console would then show "no rules found" for a token that simply lacks Zone WAF Read.
type envelope[T any] struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     T `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// Zones lists every zone the token can read.
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var zones []Zone

	// Paginated: an account with more than 50 zones returns the rest on later pages, and
	// stopping at the first would silently resolve rules for some zones and not others.
	for page := 1; ; page++ {
		var body envelope[[]struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}]
		path := fmt.Sprintf("/zones?per_page=50&page=%d", page)
		if err := c.get(ctx, path, &body); err != nil {
			return nil, err
		}

		for _, zone := range body.Result {
			zones = append(zones, Zone{ID: zone.ID, Name: strings.ToLower(zone.Name)})
		}
		if body.ResultInfo.TotalPages <= page || len(body.Result) == 0 {
			return zones, nil
		}
	}
}

// Verify reports how many zones the token can read, and fails if it cannot read at all.
//
// One call, made while an operator is watching. Saving a credential that turns out to be
// wrong used to be indistinguishable from saving one that works — the console said
// "saved" either way and the failure surfaced, if at all, in a worker log an hour later.
// A token that lists zero zones is refused too: it authenticates but can see nothing, so
// it would produce an empty table and no error anywhere.
func (c *Client) Verify(ctx context.Context) (int, error) {
	zones, err := c.Zones(ctx)
	if err != nil {
		return 0, err
	}
	if len(zones) == 0 {
		return 0, errors.New("the token is valid but can see no zones")
	}
	return len(zones), nil
}

// Rulesets lists the rulesets on a zone.
//
// The listing deliberately does NOT include each ruleset's rules — Cloudflare returns
// them only from the per-ruleset endpoint — so this is the first of two calls.
func (c *Client) Rulesets(ctx context.Context, zoneID string) ([]Ruleset, error) {
	var body envelope[[]struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Phase string `json:"phase"`
	}]
	if err := c.get(ctx, "/zones/"+url.PathEscape(zoneID)+"/rulesets", &body); err != nil {
		return nil, err
	}

	rulesets := make([]Ruleset, 0, len(body.Result))
	for _, r := range body.Result {
		rulesets = append(rulesets, Ruleset{ID: r.ID, Name: r.Name, Kind: r.Kind, Phase: r.Phase})
	}
	return rulesets, nil
}

// Rules returns one ruleset's rules.
func (c *Client) Rules(ctx context.Context, zoneID, rulesetID string) ([]Rule, error) {
	var body envelope[struct {
		Rules []struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			Action      string   `json:"action"`
			Ref         string   `json:"ref"`
			Categories  []string `json:"categories"`
		} `json:"rules"`
	}]

	path := "/zones/" + url.PathEscape(zoneID) + "/rulesets/" + url.PathEscape(rulesetID)
	if err := c.get(ctx, path, &body); err != nil {
		return nil, err
	}

	rules := make([]Rule, 0, len(body.Result.Rules))
	for _, r := range body.Result.Rules {
		rules = append(rules, Rule{
			ID:          r.ID,
			Description: strings.TrimSpace(r.Description),
			Action:      r.Action,
			Ref:         r.Ref,
			Categories:  r.Categories,
		})
	}
	return rules, nil
}

// get performs one authenticated request and decodes the envelope.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("build cloudflare request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// The URL is included and the token is NOT. An error string ends up in logs, and
		// a credential that can read a customer's WAF configuration must never be one.
		return fmt.Errorf("cloudflare %s: %w", path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare %s: status %d", path, resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("decode cloudflare %s: %w", path, err)
	}
	return checkEnvelope(out, path)
}

// checkEnvelope surfaces the errors Cloudflare reports inside a successful response.
func checkEnvelope(out any, path string) error {
	type envelopeState interface{ state() (bool, []string) }
	if state, ok := out.(envelopeState); ok {
		if ok, messages := state.state(); !ok {
			return fmt.Errorf("cloudflare %s: %s", path, strings.Join(messages, "; "))
		}
	}
	return nil
}

// state exposes the envelope's outcome to checkEnvelope.
func (e *envelope[T]) state() (bool, []string) {
	if e.Success {
		return true, nil
	}
	messages := make([]string, 0, len(e.Errors))
	for _, err := range e.Errors {
		messages = append(messages, fmt.Sprintf("%d %s", err.Code, err.Message))
	}
	if len(messages) == 0 {
		messages = append(messages, "request was not successful")
	}
	return false, messages
}
