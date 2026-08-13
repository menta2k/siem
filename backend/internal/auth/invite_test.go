package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// encodeKeysForTest builds the key half of a token from raw bytes, so a test can
// construct forms NewInviteToken would never produce.
func encodeKeysForTest(keys []byte) string {
	return base64.RawURLEncoding.EncodeToString(keys)
}

func TestInviteTokenRoundTripsItsKeys(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()

	token, err := NewInviteToken(tenantID, userID)
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}

	parsed, err := ParseInviteToken(token.Encode())
	if err != nil {
		t.Fatalf("ParseInviteToken() error = %v", err)
	}
	if parsed.TenantID != tenantID {
		t.Errorf("tenant = %s, want %s", parsed.TenantID, tenantID)
	}
	if parsed.UserID != userID {
		t.Errorf("user = %s, want %s", parsed.UserID, userID)
	}
	// The whole point of carrying the keys in the token: redemption can look the invite
	// up by primary key instead of scanning a hash column across every tenant.
	if !parsed.MatchesHash(token.SecretHash()) {
		t.Error("a round-tripped token no longer matches its own hash")
	}
}

// THE PROPERTY THAT MAKES THE KEYS SAFE TO PUBLISH. A token names its own tenant and
// user, so both are attacker-chosen — anyone can mint a well-formed token for an
// account they have picked out. The secret is what they cannot produce, and it is the
// only thing the hash comparison trusts.
func TestForgedKeysWithoutTheSecretDoNotMatch(t *testing.T) {
	victim, err := NewInviteToken(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}

	forged, err := NewInviteToken(victim.TenantID, victim.UserID)
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}

	if forged.MatchesHash(victim.SecretHash()) {
		t.Fatal("a token forged for the same account matched the victim's stored hash")
	}
}

func TestEveryIssuedTokenIsDistinct(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()

	seen := make(map[string]bool, 64)
	for i := range 64 {
		token, err := NewInviteToken(tenantID, userID)
		if err != nil {
			t.Fatalf("NewInviteToken() #%d error = %v", i, err)
		}
		hash := token.SecretHash()
		if seen[hash] {
			t.Fatalf("token #%d repeated a secret; the generator is not random", i)
		}
		seen[hash] = true
	}
}

func TestParseInviteTokenRejectsMalformedInput(t *testing.T) {
	valid, err := NewInviteToken(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}
	encoded := valid.Encode()
	keys, secret, _ := strings.Cut(encoded, ".")

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no separator", strings.ReplaceAll(encoded, ".", "")},
		{"keys only", keys},
		{"secret only", "." + secret},
		{"keys not base64", "not-base64!!." + secret},
		{"keys too short", "AAAA." + secret},
		{"nil uuids", func() string {
			var nils [32]byte
			return encodeKeysForTest(nils[:]) + "." + secret
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseInviteToken(tt.token); err == nil {
				t.Errorf("ParseInviteToken(%q) accepted a malformed token", tt.token)
			}
		})
	}
}

// Whitespace survives a copy-paste out of a chat window or an email client, and a user
// who pastes a correct token should not be told it is invalid.
func TestParseInviteTokenToleratesSurroundingWhitespace(t *testing.T) {
	token, err := NewInviteToken(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}

	parsed, err := ParseInviteToken("  " + token.Encode() + "\n")
	if err != nil {
		t.Fatalf("ParseInviteToken() error = %v", err)
	}
	if !parsed.MatchesHash(token.SecretHash()) {
		t.Error("a padded token did not match its own hash")
	}
}

// An empty stored hash must never match. A user row whose invite column was never
// written would otherwise accept any token at all.
func TestMatchesHashRejectsAnEmptyStoredHash(t *testing.T) {
	token, err := NewInviteToken(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}
	if token.MatchesHash("") {
		t.Fatal("an empty stored hash was treated as a match")
	}
}

func TestNewInviteTokenRequiresBothIdentifiers(t *testing.T) {
	if _, err := NewInviteToken(uuid.Nil, uuid.New()); err == nil {
		t.Error("NewInviteToken() accepted a nil tenant")
	}
	if _, err := NewInviteToken(uuid.New(), uuid.Nil); err == nil {
		t.Error("NewInviteToken() accepted a nil user")
	}
}

// THE BUG THIS CATCHES, which it caught while being written. Making `secret`
// unexported does NOT hide it: fmt prints unexported fields for %v, %+v, and %#v
// alike, so the original type — which had no String method, on the theory that adding
// one is what leaks credentials — printed the live token under every verb. One
// slog.Info with the token as a value would have written it to the log aggregator
// permanently. Redaction has to be explicit; Encode is the only way out.
func TestInviteTokenDoesNotLeakThroughFormatting(t *testing.T) {
	token, err := NewInviteToken(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("NewInviteToken() error = %v", err)
	}

	secret := strings.SplitN(token.Encode(), ".", 2)[1]
	for _, format := range []string{"%v", "%s", "%+v", "%#v"} {
		if rendered := fmt.Sprintf(format, token); strings.Contains(rendered, secret) {
			t.Errorf("formatting with %s printed the secret: %s", format, rendered)
		}
	}
}

func TestValidatePasswordEnforcesLength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"empty", "", true},
		{"one short", strings.Repeat("a", MinPasswordLength-1), true},
		{"at the floor", strings.Repeat("a", MinPasswordLength), false},
		{"a passphrase", "correct horse battery staple", false},
		// Counted in runes, not bytes: a short multi-byte password must not pass just
		// because its UTF-8 encoding is long.
		{"multi-byte but short", strings.Repeat("é", MinPasswordLength-1), true},
		{"multi-byte at the floor", strings.Repeat("é", MinPasswordLength), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v",
					tt.password, err, tt.wantErr)
			}
		})
	}
}
