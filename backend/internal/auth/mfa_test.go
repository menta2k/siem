package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateMFASecretProducesUsableEnrolment(t *testing.T) {
	secret, err := GenerateMFASecret("SIEM", "analyst@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}

	if secret.Secret == "" {
		t.Error("GenerateMFASecret() returned an empty secret")
	}
	if !strings.HasPrefix(secret.URI, "otpauth://totp/") {
		t.Errorf("URI = %q, want an otpauth:// provisioning URI", secret.URI)
	}
	if !strings.Contains(secret.URI, "analyst@example.com") {
		t.Errorf("URI = %q, want it to name the account", secret.URI)
	}
}

func TestGenerateMFASecretRequiresIssuerAndAccount(t *testing.T) {
	tests := []struct{ issuer, account string }{
		{"", "analyst@example.com"},
		{"SIEM", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if _, err := GenerateMFASecret(tt.issuer, tt.account); err == nil {
			t.Errorf("GenerateMFASecret(%q, %q) succeeded, want an error", tt.issuer, tt.account)
		}
	}
}

func TestVerifyMFACodeAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateMFASecret("SIEM", "analyst@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}

	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	code, err := GenerateMFACode(secret.Secret, now)
	if err != nil {
		t.Fatalf("GenerateMFACode() error = %v", err)
	}

	if err := VerifyMFACode(secret.Secret, code, now); err != nil {
		t.Errorf("VerifyMFACode() rejected the code valid at that instant: %v", err)
	}
}

// One period of drift either way is tolerated so an authenticator app with a slightly
// wrong clock still works; two periods is not, because every extra period is another
// valid code an attacker may guess.
func TestVerifyMFACodeToleratesOnePeriodOfDrift(t *testing.T) {
	secret, err := GenerateMFASecret("SIEM", "analyst@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}

	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	code, err := GenerateMFACode(secret.Secret, now)
	if err != nil {
		t.Fatalf("GenerateMFACode() error = %v", err)
	}

	tests := []struct {
		name    string
		at      time.Time
		wantErr bool
	}{
		{"one period early", now.Add(-30 * time.Second), false},
		{"one period late", now.Add(30 * time.Second), false},
		{"three periods late", now.Add(90 * time.Second), true},
		{"three periods early", now.Add(-90 * time.Second), true},
		{"an hour late", now.Add(time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyMFACode(secret.Secret, code, tt.at)
			if tt.wantErr && !errors.Is(err, ErrInvalidMFACode) {
				t.Errorf("VerifyMFACode() = %v, want ErrInvalidMFACode", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("VerifyMFACode() = %v, want nil", err)
			}
		})
	}
}

func TestVerifyMFACodeRejectsBadInput(t *testing.T) {
	secret, err := GenerateMFASecret("SIEM", "analyst@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}
	now := time.Now()

	tests := []struct {
		name   string
		secret string
		code   string
	}{
		{"empty code", secret.Secret, ""},
		{"empty secret", "", "123456"},
		{"wrong code", secret.Secret, "000000"},
		{"non-numeric", secret.Secret, "abcdef"},
		{"too short", secret.Secret, "123"},
		{"too long", secret.Secret, "12345678"},
		{"invalid secret encoding", "not-base32!!", "123456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyMFACode(tt.secret, tt.code, now); !errors.Is(err, ErrInvalidMFACode) {
				t.Errorf("VerifyMFACode() = %v, want ErrInvalidMFACode", err)
			}
		})
	}
}

// A code from one user's secret must never validate against another's.
func TestVerifyMFACodeIsSecretSpecific(t *testing.T) {
	first, err := GenerateMFASecret("SIEM", "a@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}
	second, err := GenerateMFASecret("SIEM", "b@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}

	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	code, err := GenerateMFACode(first.Secret, now)
	if err != nil {
		t.Fatalf("GenerateMFACode() error = %v", err)
	}

	if err := VerifyMFACode(second.Secret, code, now); !errors.Is(err, ErrInvalidMFACode) {
		t.Errorf("one user's TOTP code validated against another's secret: %v", err)
	}
}

func TestGenerateMFACodeRejectsInvalidSecret(t *testing.T) {
	if _, err := GenerateMFACode("not-base32!!", time.Now()); err == nil {
		t.Error("GenerateMFACode() accepted an invalid secret")
	}
}
