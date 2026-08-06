package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestFromContextReturnsStoredTenant(t *testing.T) {
	want := Tenant{ID: uuid.New(), Name: "acme"}
	ctx := WithTenant(context.Background(), want)

	got, err := FromContext(ctx)
	if err != nil {
		t.Fatalf("FromContext() error = %v, want nil", err)
	}
	if got.ID != want.ID || got.Name != want.Name {
		t.Errorf("FromContext() = %+v, want %+v", got, want)
	}
}

// The central isolation guarantee: reaching the data layer without a tenant is an
// error, never a silently unscoped query (SC-009).
func TestFromContextRejectsMissingTenant(t *testing.T) {
	_, err := FromContext(context.Background())
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("FromContext() on a bare context = %v, want ErrNoTenant", err)
	}
}

// A zero-valued tenant would scope queries to the nil UUID rather than failing, which
// is the quiet version of the same bug.
func TestFromContextRejectsNilTenantID(t *testing.T) {
	ctx := WithTenant(context.Background(), Tenant{ID: uuid.Nil, Name: "broken"})

	_, err := FromContext(ctx)
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("FromContext() with a nil tenant id = %v, want ErrNoTenant", err)
	}
}

func TestMustIDPropagatesMissingTenant(t *testing.T) {
	if _, err := MustID(context.Background()); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("MustID() on a bare context = %v, want ErrNoTenant", err)
	}

	want := uuid.New()
	got, err := MustID(WithTenant(context.Background(), Tenant{ID: want, Name: "acme"}))
	if err != nil {
		t.Fatalf("MustID() error = %v, want nil", err)
	}
	if got != want {
		t.Errorf("MustID() = %v, want %v", got, want)
	}
}

func TestHas(t *testing.T) {
	if Has(context.Background()) {
		t.Error("Has() = true for a bare context, want false")
	}
	if !Has(WithTenant(context.Background(), Tenant{ID: uuid.New()})) {
		t.Error("Has() = false for a context carrying a tenant, want true")
	}
}

// WithTenant must derive a new context rather than mutate the parent — an in-place
// change would let one request's tenant bleed into another's.
func TestWithTenantDoesNotMutateParent(t *testing.T) {
	parent := context.Background()
	_ = WithTenant(parent, Tenant{ID: uuid.New(), Name: "acme"})

	if Has(parent) {
		t.Error("WithTenant() mutated the parent context; it must return a derived one")
	}
}

// Nothing outside this package can forge a tenant by writing the context key, because
// the key type is unexported. A same-named type from another package must not match.
func TestForeignContextKeyCannotInjectTenant(t *testing.T) {
	type contextKey struct{} // deliberately identical shape, different package identity

	ctx := context.WithValue(context.Background(), contextKey{}, Tenant{ID: uuid.New()})

	if Has(ctx) {
		t.Error("a foreign context key was accepted as a tenant; the key type must be unforgeable")
	}
}

func TestTenantSeparationBetweenContexts(t *testing.T) {
	a := WithTenant(context.Background(), Tenant{ID: uuid.New(), Name: "tenant-a"})
	b := WithTenant(context.Background(), Tenant{ID: uuid.New(), Name: "tenant-b"})

	tenantA, err := FromContext(a)
	if err != nil {
		t.Fatalf("FromContext(a) error = %v", err)
	}
	tenantB, err := FromContext(b)
	if err != nil {
		t.Fatalf("FromContext(b) error = %v", err)
	}
	if tenantA.ID == tenantB.ID {
		t.Error("two independent contexts resolved to the same tenant")
	}
}
