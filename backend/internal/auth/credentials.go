package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. These follow the OWASP recommendation for interactive login:
// 19 MiB of memory, 2 iterations, 1 degree of parallelism. Memory hardness is the
// point — it is what makes an offline attack on a stolen hash expensive.
const (
	argonMemoryKiB  uint32 = 19 * 1024
	argonIterations uint32 = 2
	argonThreads    uint8  = 1
	argonKeyLength  uint32 = 32
	argonSaltLength        = 16

	argonVariant = "argon2id"
	argonVersion = 19
)

// ErrInvalidCredentials is returned for both an unknown user and a wrong password.
//
// The two cases are deliberately indistinguishable: a distinct "no such user" reply
// turns the login endpoint into a user-enumeration oracle.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// ErrMalformedHash indicates a stored hash that cannot be parsed, which means the
// record is corrupt rather than the password wrong.
var ErrMalformedHash = errors.New("auth: malformed password hash")

// HashPassword derives an argon2id hash with a fresh random salt, returning the
// standard PHC-style encoding so parameters travel with the hash and can be upgraded
// later without invalidating existing records.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth: password must not be empty")
	}

	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt,
		argonIterations, argonMemoryKiB, argonThreads, argonKeyLength)

	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVariant, argonVersion,
		argonMemoryKiB, argonIterations, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against a stored hash in constant time.
//
// The comparison uses subtle.ConstantTimeCompare: a byte-by-byte comparison leaks how
// much of the hash matched through timing, which is enough to mount an attack.
func VerifyPassword(password, encodedHash string) error {
	params, salt, want, err := decodeHash(encodedHash)
	if err != nil {
		return err
	}

	//nolint:gosec // key length is bounded by decodeHash
	got := argon2.IDKey([]byte(password), salt,
		params.iterations, params.memoryKiB, params.threads, uint32(len(want)))

	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

type argonParams struct {
	memoryKiB  uint32
	iterations uint32
	threads    uint8
}

func decodeHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", variant, version, params, salt, key
	if len(parts) != 6 || parts[1] != argonVariant {
		return argonParams{}, nil, nil, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: version: %w", ErrMalformedHash, err)
	}
	if version != argonVersion {
		return argonParams{}, nil, nil,
			fmt.Errorf("%w: unsupported argon2 version %d", ErrMalformedHash, version)
	}

	var p argonParams
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.iterations, &p.threads)
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: parameters: %w", ErrMalformedHash, err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: salt: %w", ErrMalformedHash, err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: key: %w", ErrMalformedHash, err)
	}
	if len(salt) == 0 || len(key) == 0 {
		return argonParams{}, nil, nil, ErrMalformedHash
	}

	return p, salt, key, nil
}

// NeedsRehash reports whether a stored hash was produced with weaker parameters than
// the current ones, so a successful login can transparently upgrade it.
func NeedsRehash(encodedHash string) bool {
	params, _, _, err := decodeHash(encodedHash)
	if err != nil {
		return true
	}
	return params.memoryKiB < argonMemoryKiB ||
		params.iterations < argonIterations ||
		params.threads < argonThreads
}
