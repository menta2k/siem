//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/menta2k/siem/internal/auth"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/test/support"
)

// endpoint is one route the policy must answer for.
type endpoint struct {
	name   string
	path   string
	method string
}

// A representative endpoint per capability class. If a new class of endpoint is
// added, it belongs here so every role's access to it is stated explicitly.
var endpoints = []endpoint{
	{"read feeds", "/api/v1/feeds", "GET"},
	{"create feed", "/api/v1/feeds", "POST"},
	{"search events", "/api/v1/search/events", "POST"},
	{"export results", "/api/v1/search/export", "POST"},
	{"read correlated", "/api/v1/correlated/abc", "GET"},
	{"read dashboards", "/api/v1/dashboards/overview", "GET"},
	{"create alert rule", "/api/v1/alert-rules", "POST"},
	{"acknowledge alert", "/api/v1/alerts/abc/acknowledge", "POST"},
	{"manage users", "/api/v1/admin/users", "POST"},
	{"change tenant settings", "/api/v1/admin/tenant", "PATCH"},
	{"purge data", "/api/v1/admin/purge", "POST"},
	{"read audit", "/api/v1/audit", "GET"},
	{"ingest events", "/ingest/v1/cloudflare/abc", "POST"},
}

// The complete permission matrix. Every cell is a product promise — the false cells
// as much as the true ones.
var permissionMatrix = map[string]map[string]bool{
	auth.RoleAdmin: {
		"read feeds": true, "create feed": true, "search events": true, "export results": true,
		"read correlated": true, "read dashboards": true, "create alert rule": true,
		"acknowledge alert": true, "manage users": true, "change tenant settings": true,
		"purge data": true, "read audit": true, "ingest events": false,
	},
	auth.RoleAnalyst: {
		"read feeds": true, "create feed": false, "search events": true, "export results": true,
		"read correlated": true, "read dashboards": true, "create alert rule": false,
		"acknowledge alert": true, "manage users": false, "change tenant settings": false,
		"purge data": false, "read audit": false, "ingest events": false,
	},
	auth.RoleAuditor: {
		"read feeds": true, "create feed": false, "search events": true, "export results": false,
		"read correlated": true, "read dashboards": true, "create alert rule": false,
		"acknowledge alert": false, "manage users": false, "change tenant settings": false,
		"purge data": false, "read audit": true, "ingest events": false,
	},
	auth.RoleIngestOnly: {
		"read feeds": false, "create feed": false, "search events": false, "export results": false,
		"read correlated": false, "read dashboards": false, "create alert rule": false,
		"acknowledge alert": false, "manage users": false, "change tenant settings": false,
		"purge data": false, "read audit": false, "ingest events": true,
	},
}

func TestRolePermissionMatrixAgainstRealTenant(t *testing.T) {
	_, ctx := support.SharedTenant(t, "alpha")

	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	for role, expectations := range permissionMatrix {
		for _, ep := range endpoints {
			want, stated := expectations[ep.name]
			if !stated {
				t.Fatalf("the matrix does not state whether %q may %q — "+
					"every endpoint must have an explicit decision per role", role, ep.name)
			}

			t.Run(role+"/"+ep.name, func(t *testing.T) {
				got, err := enforcer.Allow(ctx, role, ep.path, ep.method)
				if err != nil {
					t.Fatalf("Allow() error = %v", err)
				}
				if got != want {
					t.Errorf("role %q on %s %s = %v, want %v",
						role, ep.method, ep.path, got, want)
				}
			})
		}
	}
}

// An endpoint nobody granted must be unreachable by every role, so a route added
// tomorrow is protected before anyone remembers to protect it.
func TestDenyByDefaultForUngrantedEndpoints(t *testing.T) {
	_, ctx := support.SharedTenant(t, "alpha")

	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	newRoutes := []endpoint{
		{"future admin route", "/api/v1/admin/danger", "POST"},
		{"future data route", "/api/v1/raw-events/dump", "GET"},
		{"unversioned route", "/api/feeds", "GET"},
		{"root", "/", "GET"},
	}

	for role := range permissionMatrix {
		for _, ep := range newRoutes {
			allowed, err := enforcer.Allow(ctx, role, ep.path, ep.method)
			if err != nil {
				t.Fatalf("Allow() error = %v", err)
			}
			if allowed {
				t.Errorf("role %q reached ungranted route %s %s; the default must be deny",
					role, ep.method, ep.path)
			}
		}
	}
}

// Authorization without an authenticated tenant scope must be denied outright.
func TestAuthorizationRequiresTenantScope(t *testing.T) {
	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	for role := range permissionMatrix {
		allowed, err := enforcer.Allow(context.Background(), role, "/api/v1/feeds", "GET")
		if allowed {
			t.Errorf("role %q was authorized with no tenant in context", role)
		}
		if err == nil {
			t.Errorf("Allow() for role %q returned no error despite the missing tenant", role)
		}
	}
}

// Roles stored on real user records must be values the enforcer recognizes; a typo
// would produce an account that silently has no permissions at all.
func TestStoredUserRolesAreEnforceable(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	for _, role := range auth.Roles() {
		user, err := f.Users.Create(ctx, chdata.User{
			Email: role + "@alpha.example", Role: role, PasswordHash: "x",
		})
		if err != nil {
			t.Fatalf("create %s user: %v", role, err)
		}

		stored, err := f.Users.Get(ctx, user.ID)
		if err != nil {
			t.Fatalf("read back %s user: %v", role, err)
		}
		if !auth.ValidRole(stored.Role) {
			t.Errorf("stored role %q is not a role the enforcer recognizes", stored.Role)
		}

		// Every role must be able to do at least one thing, or it is dead weight
		// masquerading as an access level.
		var granted bool
		for _, ep := range endpoints {
			allowed, err := enforcer.Allow(ctx, stored.Role, ep.path, ep.method)
			if err != nil {
				t.Fatalf("Allow() error = %v", err)
			}
			if allowed {
				granted = true
				break
			}
		}
		if !granted {
			t.Errorf("role %q has no permissions at all", stored.Role)
		}
	}
}

// The ingest-only role is the most widely distributed credential, since it lives in
// third-party vendor configuration. It must reach nothing but the ingest endpoints.
func TestIngestOnlyRoleCannotReachTheConsole(t *testing.T) {
	_, ctx := support.SharedTenant(t, "alpha")

	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	consoleRoutes := []endpoint{
		{"search", "/api/v1/search/events", "POST"},
		{"events", "/api/v1/events/abc", "GET"},
		{"correlated", "/api/v1/correlated/abc", "GET"},
		{"dashboards", "/api/v1/dashboards/overview", "GET"},
		{"audit", "/api/v1/audit", "GET"},
		{"feeds", "/api/v1/feeds", "GET"},
		{"admin", "/api/v1/admin/users", "GET"},
		{"export", "/api/v1/search/export", "POST"},
	}

	for _, ep := range consoleRoutes {
		allowed, err := enforcer.Allow(ctx, auth.RoleIngestOnly, ep.path, ep.method)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if allowed {
			t.Errorf("ingest_only reached console route %s %s; these credentials sit in "+
				"vendor configuration and must grant nothing but ingest", ep.method, ep.path)
		}
	}
}

// The auditor exists to inspect the record, so it must hold no write permission at
// all — including over the audit trail itself.
func TestAuditorHoldsNoWritePermissions(t *testing.T) {
	_, ctx := support.SharedTenant(t, "alpha")

	enforcer, err := auth.NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	writes := []endpoint{
		{"create feed", "/api/v1/feeds", "POST"},
		{"update feed", "/api/v1/feeds/abc", "PATCH"},
		{"delete feed", "/api/v1/feeds/abc", "DELETE"},
		{"create rule", "/api/v1/alert-rules", "POST"},
		{"ack alert", "/api/v1/alerts/abc/acknowledge", "POST"},
		{"create user", "/api/v1/admin/users", "POST"},
		{"purge", "/api/v1/admin/purge", "POST"},
		{"export", "/api/v1/search/export", "POST"},
	}

	for _, ep := range writes {
		allowed, err := enforcer.Allow(ctx, auth.RoleAuditor, ep.path, ep.method)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if allowed {
			t.Errorf("auditor was granted write access to %s %s", ep.method, ep.path)
		}
	}
}
