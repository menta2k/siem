package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSigningKey = "test-signing-key-that-is-long-enough-32+"

// memRevocation is an in-memory RevocationStore for tests.
type memRevocation struct {
	mu      sync.Mutex
	revoked map[string]bool
	failErr error
}

func newMemRevocation() *memRevocation {
	return &memRevocation{revoked: map[string]bool{}}
}

func (m *memRevocation) Revoke(_ context.Context, tokenID string, _ time.Duration) error {
	if m.failErr != nil {
		return m.failErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[tokenID] = true
	return nil
}

func (m *memRevocation) IsRevoked(_ context.Context, tokenID string) (bool, error) {
	if m.failErr != nil {
		return false, m.failErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revoked[tokenID], nil
}

func testIdentity() Identity {
	return Identity{
		UserID:     uuid.New(),
		Email:      "analyst@example.com",
		TenantID:   uuid.New(),
		TenantName: "acme",
		Role:       RoleAnalyst,
	}
}

func newTestIssuer(t *testing.T, store RevocationStore) *TokenIssuer {
	t.Helper()
	ti, err := NewTokenIssuer(testSigningKey, 15*time.Minute, 24*time.Hour, store)
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}
	return ti
}

func TestNewTokenIssuerRejectsWeakConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		accessTTL  time.Duration
		refreshTTL time.Duration
	}{
		{"short key", "too-short", time.Minute, time.Hour},
		{"empty key", "", time.Minute, time.Hour},
		{"zero access ttl", testSigningKey, 0, time.Hour},
		{"negative refresh ttl", testSigningKey, time.Minute, -time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewTokenIssuer(tt.key, tt.accessTTL, tt.refreshTTL, nil); err == nil {
				t.Error("NewTokenIssuer() accepted an unsafe configuration")
			}
		})
	}
}

func TestIssuePairRoundTrip(t *testing.T) {
	ti := newTestIssuer(t, newMemRevocation())
	id := testIdentity()

	pair, err := ti.IssuePair(id)
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	claims, err := ti.ParseAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccess() error = %v", err)
	}
	if claims.TenantID != id.TenantID.String() {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, id.TenantID)
	}
	if claims.Role != id.Role {
		t.Errorf("Role = %q, want %q", claims.Role, id.Role)
	}
	if claims.Subject != id.UserID.String() {
		t.Errorf("Subject = %q, want %q", claims.Subject, id.UserID)
	}
}

// A token of the wrong kind must be rejected however well-signed it is. Without this,
// a refresh token would grant API access and an MFA challenge would skip the password
// step entirely.
func TestTokenPurposeIsEnforced(t *testing.T) {
	ti := newTestIssuer(t, newMemRevocation())
	id := testIdentity()

	pair, err := ti.IssuePair(id)
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	challenge, err := ti.IssueMFAChallenge(id)
	if err != nil {
		t.Fatalf("IssueMFAChallenge() error = %v", err)
	}

	if _, err := ti.ParseAccess(pair.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a refresh token was accepted as an access token: %v", err)
	}
	if _, err := ti.ParseAccess(challenge); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an MFA challenge token was accepted as an access token: %v", err)
	}
	_, err = ti.ParseRefresh(context.Background(), pair.AccessToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an access token was accepted as a refresh token: %v", err)
	}
	if _, err := ti.ParseMFAChallenge(pair.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an access token was accepted as an MFA challenge: %v", err)
	}
}

func TestParseRejectsTokenSignedWithAnotherKey(t *testing.T) {
	issuer := newTestIssuer(t, nil)
	attacker, err := NewTokenIssuer(
		"a-completely-different-signing-key-32b!!", time.Minute, time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}

	forged, err := attacker.IssuePair(testIdentity())
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	if _, err := issuer.ParseAccess(forged.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token signed with a foreign key was accepted: %v", err)
	}
}

// The alg:none attack. A token asserting no signature must never be honoured.
func TestParseRejectsUnsignedToken(t *testing.T) {
	ti := newTestIssuer(t, nil)
	id := testIdentity()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id.UserID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "siem",
		},
		TenantID: id.TenantID.String(),
		Role:     RoleAdmin,
		Purpose:  purposeAccess,
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building the unsigned token failed: %v", err)
	}

	if _, err := ti.ParseAccess(unsigned); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an alg:none token was accepted: %v", err)
	}
}

func TestParseRejectsExpiredToken(t *testing.T) {
	ti := newTestIssuer(t, newMemRevocation())
	past := time.Now().Add(-2 * time.Hour)

	pair, err := ti.WithClock(func() time.Time { return past }).IssuePair(testIdentity())
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	if _, err := ti.ParseAccess(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("ParseAccess() on an expired token = %v, want ErrTokenExpired", err)
	}
}

func TestParseRejectsMalformedToken(t *testing.T) {
	ti := newTestIssuer(t, nil)

	for _, token := range []string{"", "not.a.token", "a.b", strings.Repeat("x", 100)} {
		if _, err := ti.ParseAccess(token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("ParseAccess(%q) = %v, want ErrInvalidToken", token, err)
		}
	}
}

func TestRevokeInvalidatesRefreshToken(t *testing.T) {
	store := newMemRevocation()
	ti := newTestIssuer(t, store)
	ctx := context.Background()

	pair, err := ti.IssuePair(testIdentity())
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	if _, err := ti.ParseRefresh(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("ParseRefresh() before revocation error = %v", err)
	}
	if err := ti.Revoke(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := ti.ParseRefresh(ctx, pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("ParseRefresh() after revocation = %v, want ErrTokenRevoked", err)
	}
}

// If the revocation store cannot be reached, a token must NOT be honoured. Serving a
// possibly-revoked session because Redis is down is the wrong way to fail.
func TestParseRefreshFailsClosedWhenRevocationStoreIsDown(t *testing.T) {
	store := newMemRevocation()
	ti := newTestIssuer(t, store)

	pair, err := ti.IssuePair(testIdentity())
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	store.failErr = errors.New("redis unavailable")

	if _, err := ti.ParseRefresh(context.Background(), pair.RefreshToken); err == nil {
		t.Error("ParseRefresh() succeeded while the revocation store was " +
			"unreachable; it must fail closed")
	}
}

func TestIssuedTokensAreUnique(t *testing.T) {
	ti := newTestIssuer(t, nil)
	id := testIdentity()

	seen := map[string]bool{}
	for range 5 {
		pair, err := ti.IssuePair(id)
		if err != nil {
			t.Fatalf("IssuePair() error = %v", err)
		}
		if seen[pair.RefreshToken] {
			t.Fatal("IssuePair() produced a duplicate refresh token; each must have a unique id")
		}
		seen[pair.RefreshToken] = true
	}
}

func TestWithClockDoesNotMutateReceiver(t *testing.T) {
	ti := newTestIssuer(t, nil)
	fixed := time.Now().Add(-10 * time.Hour)

	_ = ti.WithClock(func() time.Time { return fixed })

	pair, err := ti.IssuePair(testIdentity())
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	if _, err := ti.ParseAccess(pair.AccessToken); err != nil {
		t.Errorf("WithClock() mutated the receiver: %v", err)
	}
}

func TestGenerateFeedTokenIsHighEntropyAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		token, err := GenerateFeedToken()
		if err != nil {
			t.Fatalf("GenerateFeedToken() error = %v", err)
		}
		if len(token) < 40 {
			t.Fatalf("GenerateFeedToken() = %q, too short to resist guessing", token)
		}
		if seen[token] {
			t.Fatal("GenerateFeedToken() produced a duplicate")
		}
		seen[token] = true
	}
}
