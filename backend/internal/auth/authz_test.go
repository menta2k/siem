package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

func tenantCtx(t *testing.T) context.Context {
	t.Helper()
	return tenancy.WithTenant(context.Background(),
		tenancy.Tenant{ID: uuid.New(), Name: "acme"})
}

func TestNewEnforcerLoadsEmbeddedPolicy(t *testing.T) {
	if _, err := NewEnforcer(); err != nil {
		t.Fatalf("NewEnforcer() error = %v, want nil", err)
	}
}

// The full role matrix. Each row is a permission the product promises (FR-034), or a
// denial the product promises just as firmly.
func TestRolePermissionMatrix(t *testing.T) {
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}
	ctx := tenantCtx(t)

	tests := []struct {
		name string
		role string
		obj  string
		act  string
		want bool
	}{
		// Admin configures everything.
		{"admin manages feeds", RoleAdmin, "/api/v1/feeds", "POST", true},
		{"admin changes tenant settings", RoleAdmin, "/api/v1/admin/tenant", "PATCH", true},
		{"admin reads audit", RoleAdmin, "/api/v1/audit", "GET", true},

		// Analyst investigates but must not configure.
		{"analyst searches events", RoleAnalyst, "/api/v1/search/events", "POST", true},
		{"analyst opens correlated record", RoleAnalyst, "/api/v1/correlated/abc", "GET", true},
		{"analyst acknowledges alert", RoleAnalyst, "/api/v1/alerts/abc/acknowledge", "POST", true},
		{"analyst exports", RoleAnalyst, "/api/v1/search/export", "POST", true},
		{"analyst CANNOT create a feed", RoleAnalyst, "/api/v1/feeds", "POST", false},
		{"analyst CANNOT change retention", RoleAnalyst, "/api/v1/admin/tenant", "PATCH", false},
		{"analyst CANNOT manage users", RoleAnalyst, "/api/v1/admin/users", "POST", false},
		{"analyst CANNOT create alert rules", RoleAnalyst, "/api/v1/alert-rules", "POST", false},

		// Auditor is strictly read-only, including over the record it inspects.
		{"auditor reads audit", RoleAuditor, "/api/v1/audit", "GET", true},
		{"auditor searches", RoleAuditor, "/api/v1/search/events", "POST", true},
		{"auditor CANNOT ack alerts", RoleAuditor, "/api/v1/alerts/a/acknowledge", "POST", false},
		{"auditor CANNOT export", RoleAuditor, "/api/v1/search/export", "POST", false},
		{"auditor CANNOT change anything", RoleAuditor, "/api/v1/admin/tenant", "PATCH", false},

		// Ingest-only credentials are the most widely distributed, so they grant least.
		{"ingest_only posts events", RoleIngestOnly, "/ingest/v1/cloudflare/abc", "POST", true},
		{"ingest_only CANNOT search", RoleIngestOnly, "/api/v1/search/events", "POST", false},
		{"ingest_only CANNOT read events", RoleIngestOnly, "/api/v1/events/abc", "GET", false},
		{"ingest_only CANNOT read audit", RoleIngestOnly, "/api/v1/audit", "GET", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Allow(ctx, tt.role, tt.obj, tt.act)
			if err != nil {
				t.Fatalf("Allow() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Allow(%s, %s, %s) = %v, want %v", tt.role, tt.obj, tt.act, got, tt.want)
			}
		})
	}
}

// The central property: an endpoint nobody granted access to is unreachable. A new
// route is protected before anyone remembers to protect it.
func TestDenyByDefault(t *testing.T) {
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}
	ctx := tenantCtx(t)

	for _, role := range Roles() {
		allowed, err := e.Allow(ctx, role, "/api/v1/some-endpoint-added-tomorrow", "POST")
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if allowed {
			t.Errorf("role %q was allowed on an ungranted endpoint; the default must be deny", role)
		}
	}
}

// Authorization without an authenticated tenant scope is denied, not defaulted.
func TestAllowRequiresTenantInContext(t *testing.T) {
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	allowed, err := e.Allow(context.Background(), RoleAdmin, "/api/v1/feeds", "GET")
	if allowed {
		t.Error("Allow() succeeded with no tenant in context")
	}
	if !errors.Is(err, tenancy.ErrNoTenant) {
		t.Errorf("Allow() error = %v, want ErrNoTenant", err)
	}
}

func TestAllowRejectsUnknownAndEmptyRole(t *testing.T) {
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}
	ctx := tenantCtx(t)

	for _, role := range []string{"", "superuser", "ADMIN", "admin "} {
		allowed, err := e.Allow(ctx, role, "/api/v1/admin/tenant", "PATCH")
		if err != nil {
			t.Fatalf("Allow(%q) error = %v", role, err)
		}
		if allowed {
			t.Errorf("Allow() accepted role %q; only the four defined roles may be granted", role)
		}
	}
}

func TestValidRole(t *testing.T) {
	for _, role := range Roles() {
		if !ValidRole(role) {
			t.Errorf("ValidRole(%q) = false, want true", role)
		}
	}
	for _, role := range []string{"", "root", "Admin", "analysts"} {
		if ValidRole(role) {
			t.Errorf("ValidRole(%q) = true, want false", role)
		}
	}
}

func TestRolesReturnsExactlyFour(t *testing.T) {
	if got := len(Roles()); got != 4 {
		t.Errorf("Roles() returned %d roles, want the 4 defined in FR-034", got)
	}
}
