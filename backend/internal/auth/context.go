package auth

import (
	"context"
	"sync"
)

// claimsKey carries verified token claims. Unexported so nothing outside this
// package can inject claims by writing the context key directly.
type claimsKey struct{}

// WithClaims returns a derived context carrying VERIFIED claims.
//
// Only the authentication middleware may call this, and only after ParseAccess has
// validated the signature. Placing unverified claims here would defeat every check
// downstream that trusts them.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ClaimsFromContext returns the verified claims, if any.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(*Claims)
	return claims, ok && claims != nil
}

// dummyHash is a real argon2id hash of a fixed value, computed once at first use.
//
// It exists so an unknown email costs the same work as a known one.
var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// VerifyDummyPassword performs a password verification that is guaranteed to fail.
//
// Login must take comparable time whether or not the address exists. Returning early
// for an unknown user makes the endpoint a user-enumeration oracle: an attacker
// measures the response and learns which addresses are registered, without ever
// guessing a password.
func VerifyDummyPassword() {
	dummyHashOnce.Do(func() {
		// A failure here is not actionable and must not affect the login path; the
		// empty hash simply makes the verification fail faster in that unlikely case.
		if h, err := HashPassword("dummy-password-for-constant-time-login"); err == nil {
			dummyHash = h
		}
	})
	if dummyHash == "" {
		return
	}
	// The result is discarded on purpose: this call exists only to burn the same
	// CPU time a real verification would, so login timing does not leak whether the
	// address is registered.
	_ = VerifyPassword("not-the-password", dummyHash)
}
