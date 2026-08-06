package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ErrInvalidMFACode is returned for a wrong, expired, or replayed TOTP code.
var ErrInvalidMFACode = errors.New("auth: invalid MFA code")

// totpSkew allows one 30-second period either side of now, absorbing ordinary clock
// drift between the server and an authenticator app. Widening this trades security
// for convenience: each extra period is another valid code an attacker may guess.
const totpSkew = 1

// MFASecret is a freshly generated TOTP enrolment.
type MFASecret struct {
	// Secret is the base32 shared secret. It must be encrypted before storage and
	// must never appear in a log or an API response after enrolment completes.
	Secret string
	// URI is the otpauth:// provisioning URI rendered as a QR code during enrolment.
	URI string
}

// GenerateMFASecret creates a TOTP enrolment for a user.
func GenerateMFASecret(issuer, accountEmail string) (MFASecret, error) {
	if issuer == "" || accountEmail == "" {
		return MFASecret{}, errors.New("auth: issuer and account are required to generate an MFA secret")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountEmail,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // required for authenticator-app compatibility
	})
	if err != nil {
		return MFASecret{}, fmt.Errorf("generate TOTP secret for %s: %w", accountEmail, err)
	}

	return MFASecret{Secret: key.Secret(), URI: key.URL()}, nil
}

// VerifyMFACode validates a TOTP code against the stored secret at the given time.
//
// Time is a parameter rather than read from the clock so this is deterministically
// testable — a validation function that silently depends on wall-clock time cannot be
// tested at a period boundary.
func VerifyMFACode(secret, code string, at time.Time) error {
	if secret == "" || code == "" {
		return ErrInvalidMFACode
	}

	valid, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
		Period:    30,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		// A malformed code is an invalid code, not an internal error. Reporting the
		// difference would tell an attacker which guesses were well-formed.
		return ErrInvalidMFACode
	}
	if !valid {
		return ErrInvalidMFACode
	}
	return nil
}

// GenerateMFACode produces the code valid at a given time. Used by tests and by the
// seed tool; it is never part of a request path.
func GenerateMFACode(secret string, at time.Time) (string, error) {
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    30,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("generate TOTP code: %w", err)
	}
	return code, nil
}
