package cfrules_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/cfrules"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
)

// stubTenants returns whatever the test currently wants the tenant table to say.
type stubTenants struct{ tenants []chdata.Tenant }

func (s *stubTenants) ListAll(context.Context) ([]chdata.Tenant, error) {
	return s.tenants, nil
}

// stubRuleStore records each snapshot written.
type stubRuleStore struct {
	writes    int
	lastLen   int
	lastRules []chdata.CloudflareRule
}

func (s *stubRuleStore) Replace(
	_ context.Context, _ uuid.UUID, rules []chdata.CloudflareRule, _ time.Time,
) error {
	s.writes++
	s.lastLen = len(rules)
	s.lastRules = rules
	return nil
}

// cloudflareStub answers the three calls a refresh makes.
func cloudflareStub(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones":
			_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"example.com"}],
				"result_info":{"page":1,"total_pages":1}}`)
		case "/zones/z1/rulesets":
			_, _ = fmt.Fprint(w, `{"success":true,"result":[
				{"id":"rs1","name":"Cloudflare Managed Ruleset","kind":"managed"}]}`)
		default:
			_, _ = fmt.Fprint(w, `{"success":true,"result":{"rules":[
				{"id":"r1","description":"SQLi - Body detection","action":"block"}]}}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func tenantWithToken(id uuid.UUID, ref string) chdata.Tenant {
	return chdata.Tenant{ID: id, Name: "acme", CloudflareTokenRef: ref}
}

func newTestWorker(
	t *testing.T, tenants *stubTenants, store *stubRuleStore,
) (*cfrules.Worker, secrets.Store) {
	t.Helper()

	server := cloudflareStub(t)
	secretStore := secrets.NewMemoryStore()
	worker := cfrules.NewWorker(tenants, store, secretStore, server.URL, time.Hour,
		mw.NewLogger("error", "json"))
	return worker, secretStore
}

func TestRefreshTenantStoresTheRulesItFetched(t *testing.T) {
	tenants := &stubTenants{}
	store := &stubRuleStore{}
	worker, secretStore := newTestWorker(t, tenants, store)

	ref, err := secretStore.Put(context.Background(), "cloudflare-api-token", "token-1")
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}

	count, err := worker.RefreshTenant(context.Background(),
		tenantWithToken(uuid.New(), ref))
	if err != nil {
		t.Fatalf("RefreshTenant(): %v", err)
	}

	if count != 1 || store.lastLen != 1 {
		t.Errorf("stored %d rules, reported %d, want 1", store.lastLen, count)
	}
}

// THE GAP THIS CLOSES. Saving a token used to do nothing visible for up to an hour: an
// operator pastes a credential, reloads, sees the same opaque ids, and concludes the
// feature is broken. A changed token must be picked up on the fast tick instead.
func TestAChangedTokenIsRefreshedWithoutWaitingForTheFullPass(t *testing.T) {
	tenantID := uuid.New()
	tenants := &stubTenants{}
	store := &stubRuleStore{}
	worker, secretStore := newTestWorker(t, tenants, store)
	ctx := context.Background()

	first, err := secretStore.Put(ctx, "cloudflare-api-token", "token-1")
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}
	tenants.tenants = []chdata.Tenant{tenantWithToken(tenantID, first)}

	// The startup pass takes the token as it stands.
	worker.Check(ctx, true)
	if store.writes != 1 {
		t.Fatalf("startup wrote %d snapshots, want 1", store.writes)
	}

	// An unchanged token costs nothing on the fast tick — otherwise this becomes a
	// per-minute call to Cloudflare for every deployment that has one.
	worker.Check(ctx, false)
	worker.Check(ctx, false)
	if store.writes != 1 {
		t.Errorf("an unchanged token was refreshed %d times", store.writes)
	}

	// A NEW token is picked up at once.
	second, err := secretStore.Put(ctx, "cloudflare-api-token", "token-2")
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}
	tenants.tenants = []chdata.Tenant{tenantWithToken(tenantID, second)}

	worker.Check(ctx, false)
	if store.writes != 2 {
		t.Errorf("a newly saved token was not refreshed: %d writes", store.writes)
	}
}

// A tenant with no token is the ordinary case and must cost nothing at all.
func TestATenantWithoutATokenIsSkipped(t *testing.T) {
	tenants := &stubTenants{tenants: []chdata.Tenant{{ID: uuid.New(), Name: "acme"}}}
	store := &stubRuleStore{}
	worker, _ := newTestWorker(t, tenants, store)

	worker.Check(context.Background(), true)

	if store.writes != 0 {
		t.Errorf("a tenant with no token was refreshed %d times", store.writes)
	}
}

// Removing and later restoring a token must refresh at once rather than waiting for the
// hourly pass — the reference is new, and the worker must not remember the old one.
func TestRestoringATokenRefreshesImmediately(t *testing.T) {
	tenantID := uuid.New()
	tenants := &stubTenants{}
	store := &stubRuleStore{}
	worker, secretStore := newTestWorker(t, tenants, store)
	ctx := context.Background()

	ref, err := secretStore.Put(ctx, "cloudflare-api-token", "token-1")
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}

	tenants.tenants = []chdata.Tenant{tenantWithToken(tenantID, ref)}
	worker.Check(ctx, true)

	// Removed.
	tenants.tenants = []chdata.Tenant{{ID: tenantID, Name: "acme"}}
	worker.Check(ctx, false)

	// Restored, with the same reference as before.
	tenants.tenants = []chdata.Tenant{tenantWithToken(tenantID, ref)}
	worker.Check(ctx, false)

	if store.writes != 2 {
		t.Errorf("%d writes, want 2 — a restored token must not wait for the hourly pass",
			store.writes)
	}
}

// A token that fails must not be retried every minute for an hour: a revoked credential
// would otherwise become a per-minute call to Cloudflare.
func TestAFailingTokenIsNotRetriedOnEveryTick(t *testing.T) {
	tenantID := uuid.New()
	tenants := &stubTenants{}
	store := &stubRuleStore{}

	// A server that always refuses, as a revoked token would be met with.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	secretStore := secrets.NewMemoryStore()
	ref, err := secretStore.Put(context.Background(), "cloudflare-api-token", "revoked")
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}
	tenants.tenants = []chdata.Tenant{tenantWithToken(tenantID, ref)}

	worker := cfrules.NewWorker(tenants, store, secretStore, server.URL, time.Hour,
		mw.NewLogger("error", "json"))

	worker.Check(context.Background(), true)
	worker.Check(context.Background(), false)
	worker.Check(context.Background(), false)

	if store.writes != 0 {
		t.Errorf("a failing refresh wrote %d snapshots", store.writes)
	}
}

// scopedStub answers both scopes: an account with a custom ruleset, and a zone with a
// managed one. accountStatus lets a test make the account side fail the way a zone-scoped
// token does.
func scopedStub(t *testing.T, accountStatus int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts":
			if accountStatus != http.StatusOK {
				w.WriteHeader(accountStatus)
				_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,
					"message":"Unauthorized to access requested resource"}]}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"a1","name":"Acme Inc"}],
				"result_info":{"page":1,"total_pages":1}}`)
		case "/accounts/a1/rulesets":
			_, _ = fmt.Fprint(w, `{"success":true,"result":[
				{"id":"ars1","name":"Jobs custom rules","kind":"custom",
				 "phase":"http_request_firewall_custom"}]}`)
		case "/accounts/a1/rulesets/ars1":
			_, _ = fmt.Fprint(w, `{"success":true,"result":{"rules":[
				{"id":"acct-rule-1","description":"Block html and htm file uploads",
				 "action":"log"}]}}`)
		case "/zones":
			_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"example.com"}],
				"result_info":{"page":1,"total_pages":1}}`)
		case "/zones/z1/rulesets":
			_, _ = fmt.Fprint(w, `{"success":true,"result":[
				{"id":"rs1","name":"Cloudflare Managed Ruleset","kind":"managed"}]}`)
		default:
			_, _ = fmt.Fprint(w, `{"success":true,"result":{"rules":[
				{"id":"zone-rule-1","description":"SQLi - Body detection","action":"block"}]}}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func refreshWith(t *testing.T, server *httptest.Server) *stubRuleStore {
	t.Helper()

	store := &stubRuleStore{}
	secretStore := secrets.NewMemoryStore()
	ref, err := secretStore.Put(context.Background(), "cloudflare-api-token", "token-1")
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}

	tenants := &stubTenants{tenants: []chdata.Tenant{tenantWithToken(uuid.New(), ref)}}
	worker := cfrules.NewWorker(tenants, store, secretStore, server.URL, time.Hour,
		mw.NewLogger("error", "json"))
	worker.Check(context.Background(), true)
	return store
}

// THE GAP THIS CLOSES. An account-level custom ruleset is deployed to zones through a
// phase entry point, so its rules decide real traffic while appearing in no zone's
// listing. On one production account that hid a six-rule ruleset whose members matched
// 108,599 requests in a day, including the top row of the WAF migration's false-positive
// list — which the console could only render as a bare hex id.
func TestRefreshNamesAccountLevelRules(t *testing.T) {
	store := refreshWith(t, scopedStub(t, http.StatusOK))

	if store.writes != 1 {
		t.Fatalf("writes = %d, want 1", store.writes)
	}

	byID := map[string]chdata.CloudflareRule{}
	for _, rule := range store.lastRules {
		byID[rule.RuleID] = rule
	}

	account, ok := byID["acct-rule-1"]
	if !ok {
		t.Fatalf("the account ruleset's rule was not stored: %+v", store.lastRules)
	}
	if account.Description != "Block html and htm file uploads" {
		t.Errorf("description = %q, want the name the customer gave it", account.Description)
	}
	// An account ruleset is not scoped to one zone, so naming a zone would be a guess.
	// What identifies it is the ruleset: kind `custom` with the customer's own name.
	if account.ZoneName != "" || account.ZoneID != "" {
		t.Errorf("zone = %q/%q, want empty for an account-level rule",
			account.ZoneName, account.ZoneID)
	}
	if account.RulesetKind != "custom" || account.RulesetName != "Jobs custom rules" {
		t.Errorf("ruleset = %q/%q, want the account ruleset's own identity",
			account.RulesetKind, account.RulesetName)
	}

	// And the zone rules are still there — this adds a scope, it does not replace one.
	if _, ok := byID["zone-rule-1"]; !ok {
		t.Error("the zone ruleset's rule was lost when account rules were added")
	}
}

// A zone-scoped token cannot read /accounts at all. That is a legitimate configuration,
// not a fault, and it must not cost the tenant the zone rules it CAN read.
func TestRefreshSurvivesATokenThatCannotReadAccounts(t *testing.T) {
	store := refreshWith(t, scopedStub(t, http.StatusForbidden))

	if store.writes != 1 {
		t.Fatalf("writes = %d, want the refresh to succeed on zones alone", store.writes)
	}
	for _, rule := range store.lastRules {
		if rule.RuleID == "acct-rule-1" {
			t.Fatal("an account rule appeared despite the account listing failing")
		}
	}
	if len(store.lastRules) == 0 {
		t.Error("no zone rules were stored, so a 403 on /accounts broke the whole refresh")
	}
}
