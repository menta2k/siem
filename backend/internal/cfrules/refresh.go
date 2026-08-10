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

// DefaultInterval is how often rule names are refreshed.
//
// Hourly. WAF rules change when a human edits them, which is rare but URGENT when it
// happens: a rule renamed this morning appearing under its old name all day would have
// an analyst searching for something that no longer exists. Hourly is cheap — a few API
// calls per zone — and bounds that staleness to something an operator can reason about.
const DefaultInterval = time.Hour

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
	}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "cloudflare-rules" }

// Run refreshes until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Once at startup, so a token added while the processor was down takes effect on the
	// next deploy rather than up to an hour later.
	w.refreshAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.refreshAll(ctx)
		}
	}
}

// refreshAll refreshes every tenant that has configured a token.
//
// One tenant's failure must not stop the others: a customer with a revoked token would
// otherwise cost every other customer their rule names.
func (w *Worker) refreshAll(ctx context.Context) {
	tenants, err := w.tenants.ListAll(ctx)
	if err != nil {
		w.log.Error(ctx, "cloudflare rules: cannot list tenants", "error", err)
		return
	}

	for _, tenant := range tenants {
		if tenant.CloudflareTokenRef == "" {
			continue // no token configured, which is the ordinary case
		}
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
