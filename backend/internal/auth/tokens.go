package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Token errors. All are deliberately coarse: a caller learns that a token is
// unusable, not why, so a rejected token reveals nothing about the signing key or
// the revocation set.
var (
	ErrInvalidToken = errors.New("auth: invalid token")
	ErrTokenExpired = errors.New("auth: token expired")
	ErrTokenRevoked = errors.New("auth: token revoked")
)

// tokenPurpose separates the three token kinds. A refresh token presented as an
// access token must be rejected, so the purpose is signed into the claims rather
// than inferred from where the token turned up.
const (
	purposeAccess     = "access"
	purposeRefresh    = "refresh"
	purposeMFAPending = "mfa_pending"
)

// Claims is the signed payload of an access token.
type Claims struct {
	jwt.RegisteredClaims

	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
	Email      string `json:"email"`
	Purpose    string `json:"purpose"`
}

// RevocationStore records refresh tokens that must no longer be honoured. Backed by
// Redis in production; the interface keeps the token layer testable without it.
type RevocationStore interface {
	// Revoke marks a token id unusable until at least ttl has elapsed.
	Revoke(ctx context.Context, tokenID string, ttl time.Duration) error
	// IsRevoked reports whether a token id has been revoked.
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// TokenIssuer mints and validates tokens.
type TokenIssuer struct {
	signingKey []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	revocation RevocationStore
	now        func() time.Time
}

// NewTokenIssuer constructs an issuer. now may be nil, in which case time.Now is
// used; tests inject a fixed clock.
func NewTokenIssuer(
	signingKey string,
	accessTTL, refreshTTL time.Duration,
	revocation RevocationStore,
) (*TokenIssuer, error) {
	if len(signingKey) < 32 {
		return nil, errors.New("auth: signing key must be at least 32 bytes")
	}
	if accessTTL <= 0 || refreshTTL <= 0 {
		return nil, errors.New("auth: token TTLs must be positive")
	}
	return &TokenIssuer{
		signingKey: []byte(signingKey),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		revocation: revocation,
		now:        time.Now,
	}, nil
}

// WithClock returns a copy using the supplied clock. The receiver is not modified.
func (ti *TokenIssuer) WithClock(now func() time.Time) *TokenIssuer {
	clone := *ti
	clone.now = now
	return &clone
}

// Identity is the authenticated subject a token is issued for.
type Identity struct {
	UserID     uuid.UUID
	Email      string
	TenantID   uuid.UUID
	TenantName string
	Role       string
}

// TokenPair is an issued access/refresh pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	// ExpiresAt is the ACCESS token's expiry, which is what a client schedules its
	// refresh against.
	ExpiresAt time.Time
	// RefreshExpiresAt is the refresh token's own, much later, expiry. It is separate
	// because the two are not interchangeable: a session cookie carrying the refresh
	// token and dated with the access token's expiry would evict itself within minutes
	// and log the user out exactly as if no cookie existed.
	RefreshExpiresAt time.Time
}

// IssuePair mints an access and refresh token for a fully authenticated identity
// (password AND MFA both verified).
func (ti *TokenIssuer) IssuePair(id Identity) (TokenPair, error) {
	now := ti.now()

	access, err := ti.sign(id, purposeAccess, now, ti.accessTTL, uuid.NewString())
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := ti.sign(id, purposeRefresh, now, ti.refreshTTL, uuid.NewString())
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:      access,
		RefreshToken:     refresh,
		ExpiresAt:        now.Add(ti.accessTTL),
		RefreshExpiresAt: now.Add(ti.refreshTTL),
	}, nil
}

// IssueMFAChallenge mints a short-lived token proving the password step succeeded.
//
// This token grants NOTHING except the right to present a TOTP code. Without it, a
// caller could skip straight to the MFA endpoint and brute-force codes without ever
// proving knowledge of the password.
func (ti *TokenIssuer) IssueMFAChallenge(id Identity) (string, error) {
	return ti.sign(id, purposeMFAPending, ti.now(), 5*time.Minute, uuid.NewString())
}

func (ti *TokenIssuer) sign(
	id Identity, purpose string, now time.Time, ttl time.Duration, jti string,
) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id.UserID.String(),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    "siem",
		},
		TenantID:   id.TenantID.String(),
		TenantName: id.TenantName,
		Role:       id.Role,
		Email:      id.Email,
		Purpose:    purpose,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(ti.signingKey)
	if err != nil {
		return "", fmt.Errorf("sign %s token: %w", purpose, err)
	}
	return signed, nil
}

// ParseAccess validates an access token.
func (ti *TokenIssuer) ParseAccess(token string) (*Claims, error) {
	return ti.parse(token, purposeAccess)
}

// ParseMFAChallenge validates an MFA challenge token.
func (ti *TokenIssuer) ParseMFAChallenge(token string) (*Claims, error) {
	return ti.parse(token, purposeMFAPending)
}

// ParseRefresh validates a refresh token and checks it has not been revoked.
func (ti *TokenIssuer) ParseRefresh(ctx context.Context, token string) (*Claims, error) {
	claims, err := ti.parse(token, purposeRefresh)
	if err != nil {
		return nil, err
	}
	if ti.revocation == nil {
		return claims, nil
	}

	revoked, err := ti.revocation.IsRevoked(ctx, claims.ID)
	if err != nil {
		// Fail closed: if revocation cannot be checked, the token is not honoured.
		// Serving a possibly-revoked token because Redis is down is the wrong
		// direction to fail in.
		return nil, fmt.Errorf("check token revocation: %w", err)
	}
	if revoked {
		return nil, ErrTokenRevoked
	}
	return claims, nil
}

// Revoke invalidates a refresh token for the remainder of its lifetime.
func (ti *TokenIssuer) Revoke(ctx context.Context, token string) error {
	claims, err := ti.parse(token, purposeRefresh)
	if err != nil && !errors.Is(err, ErrTokenExpired) {
		return err
	}
	if claims == nil || ti.revocation == nil {
		return nil
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return nil // already expired, nothing to revoke
	}
	if err := ti.revocation.Revoke(ctx, claims.ID, ttl); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

func (ti *TokenIssuer) parse(token, wantPurpose string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{},
		func(t *jwt.Token) (any, error) {
			// Reject any algorithm but HS256. Without this check a token signed with
			// "none" would be accepted as valid.
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%w: unexpected signing method %v", ErrInvalidToken, t.Header["alg"])
			}
			return ti.signingKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithTimeFunc(ti.now),
		jwt.WithIssuer("siem"),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	// A token of the wrong kind is invalid, however well-signed it is.
	if claims.Purpose != wantPurpose {
		return nil, fmt.Errorf("%w: expected a %s token", ErrInvalidToken, wantPurpose)
	}
	if _, err := uuid.Parse(claims.TenantID); err != nil {
		return nil, fmt.Errorf("%w: malformed tenant claim", ErrInvalidToken)
	}
	return claims, nil
}

// GenerateFeedToken produces a high-entropy bearer token for a vendor ingest feed.
// Feed tokens are stored hashed, exactly like passwords — they are credentials that
// live in third-party vendor configuration and are the most widely exposed secret in
// the system.
func GenerateFeedToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate feed token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
