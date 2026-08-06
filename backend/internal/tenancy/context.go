// Package tenancy makes tenant isolation structural rather than incidental.
//
// The design rule this package exists to enforce: repository methods take NO tenant
// parameter. A tenant identifier that can be passed can be passed wrongly, and a
// single mistake leaks one customer's security logs to another. Instead the tenant
// is derived from the verified token claim, carried in the request context, and read
// by the data layer from there.
//
// Callers that reach a repository without a tenant in context get an error, not a
// zero value, so a missing tenant fails loudly at the boundary rather than silently
// widening a query (SC-009).
package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrNoTenant is returned when tenant-scoped work is attempted without a tenant in
// context. It is deliberately not recoverable by defaulting.
var ErrNoTenant = errors.New("tenancy: no tenant in context")

// contextKey is unexported so nothing outside this package can inject a tenant by
// writing the context key directly.
type contextKey struct{}

// Tenant identifies the isolation boundary that owns the data in a request.
type Tenant struct {
	ID   uuid.UUID
	Name string
}

// WithTenant returns a derived context carrying the tenant. It never mutates the
// parent context.
//
// This must only be called from the authentication middleware (from a verified token
// claim) or from a trusted internal worker that resolved the tenant from stored data.
// Calling it with a client-supplied value would defeat the entire mechanism.
func WithTenant(ctx context.Context, t Tenant) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

// FromContext returns the tenant, or ErrNoTenant when absent.
func FromContext(ctx context.Context) (Tenant, error) {
	t, ok := ctx.Value(contextKey{}).(Tenant)
	if !ok {
		return Tenant{}, ErrNoTenant
	}
	if t.ID == uuid.Nil {
		return Tenant{}, fmt.Errorf("%w: tenant present but has a nil id", ErrNoTenant)
	}
	return t, nil
}

// MustID returns the tenant id for use in a query, or an error the repository must
// propagate. This is the single accessor the data layer uses — repositories never
// accept a tenant argument, so there is no path by which a handler can supply the
// wrong one.
func MustID(ctx context.Context) (uuid.UUID, error) {
	t, err := FromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// Has reports whether a tenant is present, for middleware that must distinguish
// "not yet authenticated" from "authenticated into a tenant".
func Has(ctx context.Context) bool {
	_, err := FromContext(ctx)
	return err == nil
}
