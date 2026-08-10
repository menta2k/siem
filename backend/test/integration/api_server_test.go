//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/asnowner"
	"github.com/menta2k/siem/internal/auth"
	"github.com/menta2k/siem/internal/cfrules"
	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/correlate"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/retention"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/server"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
	"github.com/menta2k/siem/test/support"
)

// apiRig is the real HTTP transport with every service mounted.
//
// This exists because the whole surface can compile, pass its handler tests, and still
// 404 in production: a service that is implemented but never registered is invisible
// to every test that calls the handler directly.
type apiRig struct {
	baseURL string
	tokens  *auth.TokenIssuer
	tenant  chdata.Tenant
	client  *http.Client
}

func newAPIRig(t *testing.T, name string) *apiRig {
	t.Helper()

	f := support.Shared(t)
	_, tenant := f.NewTenant(t, name)

	cfg := &conf.Config{
		Server:     conf.Server{APIPort: freePort(t), MetricsBind: "127.0.0.1"},
		Limits:     conf.Limits{QueryMaxResultRows: 1000, QueryMaxRangeDays: 90},
		ClickHouse: conf.ClickHouse{MaxExecutionTime: 5 * time.Second},
		Auth: conf.Auth{
			JWTSigningKey: strings.Repeat("k", 48),
			AccessTTL:     time.Hour, RefreshTTL: 24 * time.Hour,
			MFAIssuer: "siem-test",
		},
	}

	tokens, err := auth.NewTokenIssuer(cfg.Auth.JWTSigningKey,
		cfg.Auth.AccessTTL, cfg.Auth.RefreshTTL,
		auth.NewRedisRevocations(f.Redis, cfg.Auth.RefreshTTL))
	if err != nil {
		t.Fatalf("token issuer: %v", err)
	}
	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}

	srv := buildTestServer(t, f, cfg, tokens, enforcer)

	go func() { _ = srv.Start(context.Background()) }()
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(shutdown)
	})

	rig := &apiRig{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", cfg.Server.APIPort),
		tokens:  tokens,
		tenant:  tenant,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
	rig.waitReady(t)
	return rig
}

func buildTestServer(
	t *testing.T, f *support.Fixture, cfg *conf.Config,
	tokens *auth.TokenIssuer, enforcer *auth.Enforcer,
) *khttp.Server {
	t.Helper()

	locker := chdata.NewLocker(f.Redis)
	tenants := chdata.NewTenantRepo(f.ClickHouse, locker)
	users := chdata.NewUserRepo(f.ClickHouse, locker)
	auditLog := chdata.NewAuditRepo(f.ClickHouse, locker)
	feeds := chdata.NewFeedRepo(f.ClickHouse, locker)
	events := chdata.NewEventRepo(f.ClickHouse)
	health := chdata.NewHealthRepo(f.ClickHouse)
	// A real resolver over the real table, so the wiring that names a client's network
	// is exercised end to end. The table is empty unless a test fills it, which is the
	// ordinary case: names are decoration and every path degrades to the bare number.
	networks := asnowner.NewResolver(chdata.NewASNOwnerRepo(f.ClickHouse), time.Minute)
	// Likewise real, over the real table: a tenant with no Cloudflare token simply
	// resolves nothing, which is the ordinary case and the one worth exercising.
	ruleNames := cfrules.NewResolver(chdata.NewCloudflareRuleRepo(f.ClickHouse), time.Minute)

	adapters, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("vendor registry: %v", err)
	}

	limits := query.Limits{
		MaxResultRows: cfg.Limits.QueryMaxResultRows,
		MaxRangeDays:  cfg.Limits.QueryMaxRangeDays,
		MaxExecution:  cfg.ClickHouse.MaxExecutionTime,
	}

	return server.NewHTTPServer(server.Services{
		Auth: service.NewAuthService(users, tenants, auditLog, tokens, users,
			cfg.Auth.MFAIssuer),
		Feeds: service.NewFeedsService(feeds, events, health,
			secrets.NewMemoryStore(), auditLog, adapters),
		Search: service.NewSearchService(
			chdata.NewSearchRepo(f.ClickHouse), events, auditLog, limits, adapters, tenants,
			networks, ruleNames),
		Correlation: service.NewCorrelationService(
			chdata.NewCorrelatedRepo(f.ClickHouse), networks, ruleNames),
		Admin: service.NewAdminService(users, tenants, auditLog,
			retention.NewWorker(tenants,
				retention.Repos{
					Events:     events,
					Correlated: chdata.NewCorrelatedRepo(f.ClickHouse),
				},
				auditLog, mw.NewLogger("error", "json")),
			correlate.NewSettingsCache(tenants, correlate.DefaultSettingsTTL),
			secrets.NewMemoryStore(), "", mw.NewLogger("error", "json")),
		Alerts: service.NewAlertsService(
			chdata.NewAlertingRepo(f.ClickHouse, locker),
			alerting.NewEvaluator(alerting.NewRepoStore(
				chdata.NewAlertingRepo(f.ClickHouse, locker))),
			secrets.NewMemoryStore(), auditLog),
		Dashboards: service.NewDashboardsService(
			chdata.NewDashboardRepo(f.ClickHouse), feeds, health, limits, networks,
			chdata.NewStorageRepo(f.ClickHouse, f.Database), ruleNames),
	}, server.HTTPOptions{
		Config:      cfg,
		Health:      server.NewHealth(),
		Log:         mw.NewLogger("error", "json"),
		TokenParser: tokens,
		Authorizer:  enforcer,
		Tenants:     server.TenantGate{Tenants: tenants},
		// Deliberately generous: these tests fire many requests in a burst, and the
		// limiter's own behaviour is covered by its unit tests. What matters here is
		// that a limiter is WIRED at all, since a nil one means no limit.
		RateLimiter: rateLimiter(t, f),
	})
}

// rateLimiter builds a permissive limiter for the rig.
func rateLimiter(t *testing.T, f *support.Fixture) *mw.RateLimiter {
	t.Helper()

	limiter, err := mw.NewRateLimiter(f.Redis,
		mw.LimitScope{Name: "tenant", Limit: 100_000, Window: time.Minute})
	if err != nil {
		t.Fatalf("build rate limiter: %v", err)
	}
	return limiter
}

func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

func (r *apiRig) waitReady(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := r.client.Get(r.baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the api server did not start")
}

// token mints an access token for a role in the rig's tenant.
func (r *apiRig) token(t *testing.T, role string) string {
	t.Helper()

	pair, err := r.tokens.IssuePair(auth.Identity{
		UserID:     uuid.New(),
		TenantID:   r.tenant.ID,
		TenantName: r.tenant.Name,
		Email:      role + "@example.com",
		Role:       role,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return pair.AccessToken
}

func (r *apiRig) do(
	t *testing.T, method, path, token string, body io.Reader,
) (int, map[string]any) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		context.Background(), method, r.baseURL+path, body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	decoded := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return resp.StatusCode, decoded
}

// tenantContext scopes a background context to a tenant, for the direct repository
// access these tests need to set up preconditions the API itself will not perform.
func tenantContext(tenant chdata.Tenant) context.Context {
	return tenancy.WithTenant(context.Background(),
		tenancy.Tenant{ID: tenant.ID, Name: tenant.Name})
}

// ---------------------------------------------------------------- the tests

// Every route in the contract must be mounted. A service that is implemented but never
// registered returns 404 in production while every handler test passes.
func TestEveryServiceIsMounted(t *testing.T) {
	rig := newAPIRig(t, "api-mounted")
	token := rig.token(t, "admin")

	routes := []struct {
		method, path string
		body         string
	}{
		{http.MethodGet, "/api/v1/feeds", ""},
		{http.MethodPost, "/api/v1/search/events",
			`{"timeRange":{"from":"2026-08-06T11:00:00Z","to":"2026-08-06T12:00:00Z"}}`},
		{http.MethodPost, "/api/v1/search/correlated",
			`{"timeRange":{"from":"2026-08-06T11:00:00Z","to":"2026-08-06T12:00:00Z"}}`},
		{http.MethodGet, "/api/v1/correlated?timeRange.from=2026-08-06T11:00:00Z" +
			"&timeRange.to=2026-08-06T12:00:00Z", ""},
		{http.MethodGet, "/api/v1/dashboards/overview?timeRange.from=2026-08-06T11:00:00Z" +
			"&timeRange.to=2026-08-06T12:00:00Z", ""},
		{http.MethodGet, "/api/v1/dashboards/rules?timeRange.from=2026-08-06T11:00:00Z" +
			"&timeRange.to=2026-08-06T12:00:00Z", ""},
		{http.MethodGet, "/api/v1/dashboards/feed-health?timeRange.from=2026-08-06T11:00:00Z" +
			"&timeRange.to=2026-08-06T12:00:00Z", ""},
		{http.MethodGet, "/api/v1/alert-rules", ""},
		{http.MethodGet, "/api/v1/alerts?timeRange.from=2026-08-06T11:00:00Z" +
			"&timeRange.to=2026-08-06T12:00:00Z", ""},
		{http.MethodGet, "/api/v1/admin/users", ""},
		{http.MethodGet, "/api/v1/admin/tenant", ""},
		{http.MethodGet, "/api/v1/audit?range.from=2026-08-06T11:00:00Z" +
			"&range.to=2026-08-06T12:00:00Z", ""},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var body io.Reader
			if route.body != "" {
				body = strings.NewReader(route.body)
			}
			status, payload := rig.do(t, route.method, route.path, token, body)
			if status == http.StatusNotFound {
				t.Fatalf("route is not mounted: %d %v", status, payload)
			}
			if status >= 500 {
				t.Fatalf("route failed: %d %v", status, payload)
			}
		})
	}
}

// The probes must not require a token: an orchestrator cannot supply one, and a
// metrics endpoint that needs one cannot be scraped.
func TestOperationalRoutesNeedNoToken(t *testing.T) {
	rig := newAPIRig(t, "api-ops")

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		status, _ := rig.do(t, http.MethodGet, path, "", nil)
		if status == http.StatusUnauthorized || status == http.StatusNotFound {
			t.Errorf("%s returned %d; probes must be reachable without credentials",
				path, status)
		}
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	rig := newAPIRig(t, "api-unauth")

	status, payload := rig.do(t, http.MethodGet, "/api/v1/feeds", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if payload["code"] != mw.CodeUnauthenticated {
		t.Errorf("code = %v, want %q", payload["code"], mw.CodeUnauthenticated)
	}
}

func TestGarbageTokensAreRejected(t *testing.T) {
	rig := newAPIRig(t, "api-badtoken")

	for _, token := range []string{"not-a-jwt", "a.b.c", strings.Repeat("x", 500)} {
		status, _ := rig.do(t, http.MethodGet, "/api/v1/feeds", token, nil)
		if status != http.StatusUnauthorized {
			t.Errorf("token %q gave %d, want 401", token[:min(len(token), 12)], status)
		}
	}
}

// The Casbin policy is written against path TEMPLATES. If the middleware passed the
// substituted path instead, every parameterised route would be denied — and the policy
// line would look correct while nothing matched it.
func TestRoleEnforcementUsesPathTemplates(t *testing.T) {
	rig := newAPIRig(t, "api-rbac")

	// An auditor may read a feed but must not delete one.
	feedID := uuid.New().String()

	status, _ := rig.do(t, http.MethodGet, "/api/v1/feeds/"+feedID,
		rig.token(t, "auditor"), nil)
	if status == http.StatusForbidden {
		t.Error("an auditor was denied a read the policy grants; the path template " +
			"is probably not reaching the enforcer")
	}

	status, payload := rig.do(t, http.MethodDelete, "/api/v1/feeds/"+feedID,
		rig.token(t, "auditor"), nil)
	if status != http.StatusForbidden {
		t.Fatalf("an auditor deleted a feed: status %d %v", status, payload)
	}
	if payload["code"] != mw.CodePermissionDenied {
		t.Errorf("code = %v, want %q", payload["code"], mw.CodePermissionDenied)
	}
}

// Errors must leave through the encoder in the platform's envelope, or the contract's
// stable error codes are only stable in the handler tests.
func TestErrorsUseThePlatformEnvelope(t *testing.T) {
	rig := newAPIRig(t, "api-errors")

	status, payload := rig.do(t, http.MethodPost, "/api/v1/search/events",
		rig.token(t, "analyst"), strings.NewReader(`{}`))

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing time range", status)
	}
	if payload["code"] != mw.CodeTimeRangeRequired {
		t.Errorf("code = %v, want %q", payload["code"], mw.CodeTimeRangeRequired)
	}
	if _, ok := payload["message"].(string); !ok {
		t.Error("the error envelope carries no message")
	}
}

// A suspended tenant's outstanding tokens stay cryptographically valid until they
// expire, so the suspension has to be enforced per request.
func TestSuspendedTenantIsRefused(t *testing.T) {
	rig := newAPIRig(t, "api-suspended")
	token := rig.token(t, "admin")

	if status, _ := rig.do(t, http.MethodGet, "/api/v1/feeds", token, nil); status != 200 {
		t.Fatalf("the tenant was not usable before suspension: %d", status)
	}

	f := support.Shared(t)
	ctx := tenantContext(rig.tenant)
	if _, err := chdata.NewTenantRepo(f.ClickHouse, chdata.NewLocker(f.Redis)).
		Update(ctx, func(tn chdata.Tenant) chdata.Tenant {
			tn.Status = chdata.TenantStatusSuspended
			return tn
		}); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}
	f.Sync(t, "tenants")

	status, payload := rig.do(t, http.MethodGet, "/api/v1/feeds", token, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a suspended tenant", status)
	}
	if payload["code"] != mw.CodeTenantSuspended {
		t.Errorf("code = %v, want %q", payload["code"], mw.CodeTenantSuspended)
	}
}
