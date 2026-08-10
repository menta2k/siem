package cfrules

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
)

// DefaultInterval is how often rule names are refreshed in full.
//
// Hourly. WAF rules change when a human edits them, which is rare but URGENT when it
// happens: a rule renamed this morning appearing under its old name all day would have
// an analyst searching for something that no longer exists. Hourly is cheap — a few API
// calls per zone — and bounds that staleness to something an operator can reason about.
const DefaultInterval = time.Hour

// checkInterval is how often the worker looks for a CHANGED token.
//
// A full refresh walks every zone's rulesets and takes minutes, so it stays hourly. This
// is the cheap question in between: one query for the tenant list, comparing each token
// reference against the last one seen.
//
// It exists because saving a token used to do NOTHING VISIBLE for up to an hour. An
// operator pastes a credential, reloads the console, sees the same opaque ids, and
// reasonably concludes the feature is broken — the most likely moment for someone to
// give up on it is the minute after they set it up. A minute's wait is a pause; an
// hour's is a failure.
const checkInterval = time.Minute

// TenantSource lists the tenants whose rules may need refreshing.
type TenantSource interface {
	ListAll(ctx context.Context) ([]chdata.Tenant, error)
}

// RuleStore persists a tenant's rule snapshot.
type RuleStore interface {
	Replace(ctx context.Context, tenantID uuid.UUID, rules []chdata.CloudflareRule, at time.Time) error
}

// Worker keeps every tenant's Cloudflare rule names current.
type Worker struct {
	tenants TenantSource
	store   RuleStore
	secrets secrets.Store
	log     mw.Logger

	apiBase  string
	interval time.Duration
	now      func() time.Time
	// seenTokens is the token reference last refreshed for each tenant, so a token that
	// was just changed can be told apart from one that has been in place for weeks.
	seenTokens map[uuid.UUID]string
	// newClient is swappable so the worker can be driven against a test server without
	// reaching Cloudflare.
	newClient func(token, base string) *Client
}

// NewWorker constructs the refresh worker.
func NewWorker(
	tenants TenantSource, store RuleStore, secretStore secrets.Store,
	apiBase string, interval time.Duration, log mw.Logger,
) *Worker {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Worker{
		tenants: tenants, store: store, secrets: secretStore, log: log,
		apiBase: apiBase, interval: interval, now: time.Now, newClient: NewClient,
		seenTokens: map[uuid.UUID]string{},
	}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "cloudflare-rules" }

// Run refreshes until the context is cancelled.
//
// Two cadences, one loop. The full refresh stays on the configured interval because it
// walks every zone's rulesets and costs minutes; the fast tick only asks whether anyone's
// token has CHANGED, which is one query and nothing else. Together they mean a newly
// saved token takes effect within a minute while a stable one is re-read hourly.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// Once at startup, so a token added while the processor was down takes effect on the
	// next deploy rather than at the next tick.
	w.Check(ctx, true)
	nextFull := w.now().Add(w.interval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			full := !w.now().Before(nextFull)
			if full {
				nextFull = w.now().Add(w.interval)
			}
			w.Check(ctx, full)
		}
	}
}

// Check runs one pass.
//
// `full` re-reads every configured token; otherwise only the tenants whose token has
// CHANGED since the last pass are refreshed. Exported so the pass can be driven directly
// — by a test, or by anything that needs a refresh to happen now rather than on the tick.
func (w *Worker) Check(ctx context.Context, full bool) {
	scope := changedTokensOnly
	if full {
		scope = allTenants
	}
	w.refreshAll(ctx, scope)
}

// refreshScope selects which tenants a pass considers.
type refreshScope int

const (
	// allTenants re-reads every configured token, which is the hourly pass.
	allTenants refreshScope = iota
	// changedTokensOnly refreshes just the tenants whose token reference differs from
	// the one last refreshed — the newly-saved-token case, and nothing else.
	changedTokensOnly
)

// refreshAll refreshes every tenant that has configured a token.
//
// One tenant's failure must not stop the others: a customer with a revoked token would
// otherwise cost every other customer their rule names.
func (w *Worker) refreshAll(ctx context.Context, scope refreshScope) {
	tenants, err := w.tenants.ListAll(ctx)
	if err != nil {
		w.log.Error(ctx, "cloudflare rules: cannot list tenants", "error", err)
		return
	}

	for _, tenant := range tenants {
		if tenant.CloudflareTokenRef == "" {
			// No token configured, which is the ordinary case. Forgetting any reference
			// seen before means a token that is removed and later restored is treated as
			// new, and refreshed at once rather than at the next hour.
			delete(w.seenTokens, tenant.ID)
			continue
		}
		if scope == changedTokensOnly && w.seenTokens[tenant.ID] == tenant.CloudflareTokenRef {
			continue
		}

		// Recorded BEFORE the attempt, not after. A token that fails must not be retried
		// every minute for an hour — a revoked credential would otherwise become a
		// per-minute call to Cloudflare from every deployment that has one.
		w.seenTokens[tenant.ID] = tenant.CloudflareTokenRef

		count, err := w.RefreshTenant(ctx, tenant)
		if err != nil {
			// WARN, not ERROR: the previous snapshot is still being served, so this
			// degrades a label rather than breaking anything. A revoked token is a
			// customer action, not a platform fault.
			w.log.Warn(ctx, "cloudflare rules: refresh failed, keeping the existing names",
				"error", err, "tenant_id", tenant.ID)
			continue
		}
		w.log.Info(ctx, "cloudflare rules: refreshed",
			"tenant_id", tenant.ID, "rules", count)
	}
}

// RefreshTenant fetches and stores one tenant's rules.
func (w *Worker) RefreshTenant(ctx context.Context, tenant chdata.Tenant) (int, error) {
	token, err := w.secrets.Resolve(ctx, tenant.CloudflareTokenRef)
	if err != nil {
		return 0, fmt.Errorf("resolve cloudflare token: %w", err)
	}
	if token == "" {
		return 0, errors.New("cloudflare token reference resolved to nothing")
	}

	rules, err := w.fetch(ctx, w.newClient(token, w.apiBase))
	if err != nil {
		return 0, err
	}
	if len(rules) == 0 {
		return 0, errors.New("no rules found for any zone the token can read")
	}

	if err := w.store.Replace(ctx, tenant.ID, rules, w.now()); err != nil {
		return 0, fmt.Errorf("store cloudflare rules: %w", err)
	}
	return len(rules), nil
}

// fetch walks every zone's rulesets and collects their rules.
//
// A failure on ONE zone or ruleset is collected and skipped rather than abandoning the
// run: a token scoped to three of a customer's five zones should still name the rules of
// those three, and reporting nothing would be a worse answer than a partial one. The
// errors are returned alongside the rules so the caller can log what was missed.
func (w *Worker) fetch(ctx context.Context, client *Client) ([]chdata.CloudflareRule, error) {
	zones, err := client.Zones(ctx)
	if err != nil {
		return nil, err
	}

	var rules []chdata.CloudflareRule
	for _, zone := range zones {
		rulesets, err := client.Rulesets(ctx, zone.ID)
		if err != nil {
			w.log.Warn(ctx, "cloudflare rules: zone skipped",
				"error", err, "zone", zone.Name)
			continue
		}

		for _, ruleset := range rulesets {
			fetched, err := client.Rules(ctx, zone.ID, ruleset.ID)
			if err != nil {
				w.log.Warn(ctx, "cloudflare rules: ruleset skipped",
					"error", err, "zone", zone.Name, "ruleset", ruleset.Name)
				continue
			}
			rules = append(rules, toRows(zone, ruleset, fetched)...)
		}
	}
	return rules, nil
}

// toRows projects one ruleset's rules onto storage rows.
func toRows(zone Zone, ruleset Ruleset, rules []Rule) []chdata.CloudflareRule {
	out := make([]chdata.CloudflareRule, 0, len(rules))
	for _, rule := range rules {
		// A rule with no description names nothing, and storing it would make the
		// resolver report a hit that renders as an empty label — worse than the bare id,
		// which at least looks like an identifier.
		if rule.Description == "" {
			continue
		}
		out = append(out, chdata.CloudflareRule{
			ZoneName:    zone.Name,
			ZoneID:      zone.ID,
			RuleID:      rule.ID,
			RulesetID:   ruleset.ID,
			RulesetName: ruleset.Name,
			RulesetKind: ruleset.Kind,
			Description: rule.Description,
			Action:      rule.Action,
			Ref:         rule.Ref,
			Categories:  rule.Categories,
		})
	}
	return out
}
