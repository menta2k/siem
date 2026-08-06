// Package auth_test exercises credential handling from outside the package, so the
// tests can only use the exported surface a caller actually has.
package auth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/auth"
)

func TestHashPasswordProducesVerifiableHash(t *testing.T) {
	const password = "correct horse battery staple"

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := auth.VerifyPassword(password, hash); err != nil {
		t.Errorf("VerifyPassword() rejected the password it just hashed: %v", err)
	}
}

// A stored hash must never contain the password, and must carry its parameters so
// they can be strengthened later without invalidating existing records.
func TestHashFormatAndOpacity(t *testing.T) {
	const password = "s3cret-passphrase"

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if strings.Contains(hash, password) {
		t.Fatal("the encoded hash contains the plaintext password")
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("hash = %q, want the argon2id PHC encoding", hash)
	}
	if !strings.Contains(hash, "m=19456,t=2,p=1") {
		t.Errorf("hash = %q, want it to record the derivation parameters", hash)
	}
}

// Equal passwords must not produce equal hashes, or a stolen table reveals which
// accounts share a password.
func TestHashPasswordUsesFreshSalt(t *testing.T) {
	const password = "same-password-twice"

	first, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	second, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if first == second {
		t.Fatal("hashing the same password twice produced identical hashes; the salt is not random")
	}
	for _, h := range []string{first, second} {
		if err := auth.VerifyPassword(password, h); err != nil {
			t.Errorf("VerifyPassword() failed for a valid hash: %v", err)
		}
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := auth.HashPassword("the-right-one")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	tests := []string{"the-wrong-one", "", "the-right-on", "the-right-one ", "THE-RIGHT-ONE"}
	for _, password := range tests {
		t.Run(password, func(t *testing.T) {
			err := auth.VerifyPassword(password, hash)
			if !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Errorf("VerifyPassword(%q) = %v, want ErrInvalidCredentials", password, err)
			}
		})
	}
}

func TestHashPasswordRejectsEmptyPassword(t *testing.T) {
	if _, err := auth.HashPassword(""); err == nil {
		t.Error("HashPassword(\"\") succeeded; an empty password must be rejected")
	}
}

// A corrupt stored hash is a data problem, not a wrong password — the two must be
// distinguishable so a corrupt record is not silently reported as a failed login.
func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not a hash", "hunter2"},
		{"wrong variant", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$a2V5"},
		{"too few segments", "$argon2id$v=19$m=19456,t=2,p=1"},
		{"bad version", "$argon2id$v=99$m=19456,t=2,p=1$c2FsdA$a2V5"},
		{"unparseable params", "$argon2id$v=19$m=abc,t=2,p=1$c2FsdA$a2V5"},
		{"bad base64 salt", "$argon2id$v=19$m=19456,t=2,p=1$!!!$a2V5"},
		{"bad base64 key", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.VerifyPassword("anything", tt.hash)
			if !errors.Is(err, auth.ErrMalformedHash) {
				t.Errorf("VerifyPassword() with %s hash = %v, want ErrMalformedHash", tt.name, err)
			}
		})
	}
}

// Verification time must not depend on how much of the hash matched. This is a smoke
// test, not a statistical proof: it catches a switch to a short-circuiting compare.
func TestVerifyPasswordTimingIsIndependentOfPrefix(t *testing.T) {
	hash, err := auth.HashPassword("aaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	measure := func(password string) time.Duration {
		const runs = 5
		start := time.Now()
		for range runs {
			_ = auth.VerifyPassword(password, hash) //nolint:errcheck // timing only
		}
		return time.Since(start) / runs
	}

	nearMiss := measure("aaaaaaaaaaaaaaaaaaab")
	farMiss := measure("zzzzzzzzzzzzzzzzzzzz")

	ratio := float64(nearMiss) / float64(farMiss)
	if ratio < 0.5 || ratio > 2.0 {
		t.Errorf("verification time varies with the guess "+
			"(near/far ratio %.2f); the comparison may be short-circuiting", ratio)
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := auth.HashPassword("some-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if auth.NeedsRehash(current) {
		t.Error("NeedsRehash() = true for a hash produced with the current parameters")
	}

	weak := "$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5"
	if !auth.NeedsRehash(weak) {
		t.Error("NeedsRehash() = false for a hash with weaker parameters; " +
			"it should be upgraded on next login")
	}

	if !auth.NeedsRehash("garbage") {
		t.Error("NeedsRehash() = false for an unparseable hash; it must be replaced")
	}
}
