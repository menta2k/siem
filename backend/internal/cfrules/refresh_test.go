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
	writes  int
	lastLen int
}

func (s *stubRuleStore) Replace(
	_ context.Context, _ uuid.UUID, rules []chdata.CloudflareRule, _ time.Time,
) error {
	s.writes++
	s.lastLen = len(rules)
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
