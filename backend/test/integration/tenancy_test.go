//go:build integration

// Package integration exercises the data layer against real ClickHouse, Redis, and
// Redpanda containers. Mocks are deliberately avoided: ReplacingMergeTree's eventual
// deduplication and ClickHouse's absent uniqueness constraints are exactly the
// behaviours these tests exist to pin down.
package integration

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/test/support"
)

// A repository call without a tenant in context must fail, not run unscoped.
// An unscoped query would read every tenant's data at once (SC-009).
func TestRepositoryRefusesCallWithoutTenant(t *testing.T) {
	f := support.Shared(t)
	bare := context.Background()

	t.Run("user get", func(t *testing.T) {
		_, err := f.Users.Get(bare, uuid.New())
		if !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("Users.Get() without a tenant = %v, want ErrNoTenant", err)
		}
	})

	t.Run("user list", func(t *testing.T) {
		_, err := f.Users.List(bare, 10)
		if !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("Users.List() without a tenant = %v, want ErrNoTenant", err)
		}
	})

	t.Run("user create", func(t *testing.T) {
		_, err := f.Users.Create(bare, chdata.User{Email: "a@example.com", Role: "analyst"})
		if !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("Users.Create() without a tenant = %v, want ErrNoTenant", err)
		}
	})

	t.Run("tenant get", func(t *testing.T) {
		_, err := f.Tenants.Get(bare)
		if !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("Tenants.Get() without a tenant = %v, want ErrNoTenant", err)
		}
	})

	t.Run("audit append", func(t *testing.T) {
		_, err := f.Audit.Append(bare, validAuditRecord())
		if !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("Audit.Append() without a tenant = %v, want ErrNoTenant", err)
		}
	})

	t.Run("audit list", func(t *testing.T) {
		_, err := f.Audit.List(bare, chdata.ListFilter{})
		if !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("Audit.List() without a tenant = %v, want ErrNoTenant", err)
		}
	})
}

// The central isolation guarantee: tenant A must never see tenant B's rows, and must
// not be able to learn that they exist (SC-009).
func TestTenantIsolation(t *testing.T) {
	f := support.Shared(t)

	ctxA, tenantA := f.NewTenant(t, "alpha")
	ctxB, tenantB := f.NewTenant(t, "beta")

	userA, err := f.Users.Create(ctxA, chdata.User{
		Email: "analyst@alpha.example", Role: "analyst", PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create user in tenant A: %v", err)
	}
	userB, err := f.Users.Create(ctxB, chdata.User{
		Email: "analyst@beta.example", Role: "analyst", PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create user in tenant B: %v", err)
	}

	t.Run("cannot read another tenant's user by id", func(t *testing.T) {
		// Even with B's exact user id, A must get "not found" — not the row, and not
		// a permission error that would confirm the id exists somewhere.
		_, err := f.Users.Get(ctxA, userB.ID)
		if !errors.Is(err, chdata.ErrNotFound) {
			t.Errorf("tenant A reading tenant B's user = %v, want ErrNotFound", err)
		}
	})

	t.Run("list returns only own users", func(t *testing.T) {
		usersA, err := f.Users.List(ctxA, 100)
		if err != nil {
			t.Fatalf("list users for tenant A: %v", err)
		}
		for _, u := range usersA {
			if u.TenantID != tenantA.ID {
				t.Errorf("tenant A's list contained a user from tenant %s", u.TenantID)
			}
			if u.ID == userB.ID {
				t.Error("tenant A's list leaked tenant B's user")
			}
		}
		if len(usersA) != 1 || usersA[0].ID != userA.ID {
			t.Errorf("tenant A saw %d users, want exactly its own 1", len(usersA))
		}
	})

	t.Run("cannot update another tenant's user", func(t *testing.T) {
		_, err := f.Users.Update(ctxA, userB.ID, func(u chdata.User) chdata.User {
			u.Role = "admin"
			return u
		})
		if !errors.Is(err, chdata.ErrNotFound) {
			t.Errorf("tenant A updating tenant B's user = %v, want ErrNotFound", err)
		}

		// Confirm B's user was genuinely untouched, not merely reported as absent.
		stillB, err := f.Users.Get(ctxB, userB.ID)
		if err != nil {
			t.Fatalf("re-read tenant B's user: %v", err)
		}
		if stillB.Role != "analyst" {
			t.Errorf("tenant B's user role = %q, want it unchanged at %q", stillB.Role, "analyst")
		}
	})

	t.Run("settings updates do not cross tenants", func(t *testing.T) {
		if _, err := f.Tenants.Update(ctxA, func(tn chdata.Tenant) chdata.Tenant {
			tn.RawRetentionDays = 7
			return tn
		}); err != nil {
			t.Fatalf("update tenant A: %v", err)
		}

		b, err := f.Tenants.Get(ctxB)
		if err != nil {
			t.Fatalf("read tenant B: %v", err)
		}
		if b.RawRetentionDays != 30 {
			t.Errorf("tenant B retention = %d, want it unaffected at 30", b.RawRetentionDays)
		}
		if b.ID != tenantB.ID {
			t.Errorf("Tenants.Get() in context B returned tenant %s", b.ID)
		}
	})

	t.Run("audit entries do not cross tenants", func(t *testing.T) {
		if _, err := f.Audit.Append(ctxA, validAuditRecord()); err != nil {
			t.Fatalf("append audit for tenant A: %v", err)
		}

		entriesB, err := f.Audit.List(ctxB, auditRange())
		if err != nil {
			t.Fatalf("list audit for tenant B: %v", err)
		}
		for _, e := range entriesB {
			if e.TenantID != tenantB.ID {
				t.Errorf("tenant B's audit list contained an entry from tenant %s", e.TenantID)
			}
		}
	})
}

// A user record's tenant is fixed at creation from context and must not be settable
// by the caller, or a client could plant a row in someone else's tenant.
func TestCallerCannotChooseTenantOnWrite(t *testing.T) {
	f := support.Shared(t)

	ctxA, tenantA := f.NewTenant(t, "alpha")
	_, tenantB := f.NewTenant(t, "beta")

	created, err := f.Users.Create(ctxA, chdata.User{
		// Deliberately claim tenant B while operating in tenant A's context.
		TenantID: tenantB.ID,
		Email:    "attacker@alpha.example",
		Role:     "analyst",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if created.TenantID != tenantA.ID {
		t.Errorf("user was created in tenant %s, want the context's tenant %s — "+
			"a caller-supplied tenant id must be ignored", created.TenantID, tenantA.ID)
	}
}

// ClickHouse has no unique constraint, so uniqueness is enforced by the application
// under a Redis lock. This proves concurrent creates cannot both succeed.
func TestConcurrentUserCreatesEnforceEmailUniqueness(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	const attempts = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
		other     []error
	)

	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.Users.Create(ctx, chdata.User{
				Email: "contested@alpha.example", Role: "analyst", PasswordHash: "x",
			})

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, chdata.ErrEmailTaken):
				conflicts++
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected errors during concurrent create: %v", other)
	}
	if succeeded != 1 {
		t.Errorf("%d concurrent creates succeeded, want exactly 1 — "+
			"the per-entity lock is not serialising the uniqueness check", succeeded)
	}
	if conflicts != attempts-1 {
		t.Errorf("got %d conflicts, want %d", conflicts, attempts-1)
	}
}

// Email uniqueness is per tenant: the same address in two tenants is legitimate.
func TestSameEmailAllowedInDifferentTenants(t *testing.T) {
	f := support.Shared(t)
	ctxA, _ := f.NewTenant(t, "alpha")
	ctxB, _ := f.NewTenant(t, "beta")

	const shared = "consultant@example.com"

	if _, err := f.Users.Create(ctxA, chdata.User{Email: shared, Role: "analyst"}); err != nil {
		t.Fatalf("create in tenant A: %v", err)
	}
	if _, err := f.Users.Create(ctxB, chdata.User{Email: shared, Role: "auditor"}); err != nil {
		t.Errorf("create in tenant B with the same email = %v, want success — "+
			"uniqueness is scoped per tenant", err)
	}
}

// Case and whitespace must not defeat the uniqueness check.
func TestEmailUniquenessIgnoresCaseAndWhitespace(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	_, err := f.Users.Create(ctx, chdata.User{Email: "Analyst@Example.com", Role: "analyst"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	variants := []string{"analyst@example.com", "ANALYST@EXAMPLE.COM", "  analyst@example.com  "}
	for _, variant := range variants {
		_, err := f.Users.Create(ctx, chdata.User{Email: variant, Role: "analyst"})
		if !errors.Is(err, chdata.ErrEmailTaken) {
			t.Errorf("Create(%q) = %v, want ErrEmailTaken", variant, err)
		}
	}
}

// ReplacingMergeTree keeps every version until a merge. A read must return the
// newest, not an arbitrary one — otherwise a role change could silently revert.
func TestUpdateReadsBackNewestVersion(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	user, err := f.Users.Create(ctx, chdata.User{
		Email: "analyst@alpha.example", Role: "analyst", PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	for i, role := range []string{"auditor", "admin", "analyst"} {
		if _, err := f.Users.Update(ctx, user.ID, func(u chdata.User) chdata.User {
			u.Role = role
			return u
		}); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}

		got, err := f.Users.Get(ctx, user.ID)
		if err != nil {
			t.Fatalf("read after update %d: %v", i, err)
		}
		if got.Role != role {
			t.Fatalf("after update %d role = %q, want %q — the read is not using FINAL",
				i, got.Role, role)
		}
		if got.Version != uint64(i+2) {
			t.Errorf("version = %d, want %d", got.Version, i+2)
		}
	}
}
