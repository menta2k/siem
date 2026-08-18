package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Sealing a secret so it can be written somewhere it would otherwise not belong.
//
// The package rule is that a vendor credential is never persisted in the analytical
// store, for three reasons: it would sit beside the customer's logs, share their
// retention, and be readable from every query path. Encryption answers all three — what
// is written is ciphertext, and the key lives in the service's environment, which
// ClickHouse has no access to. What is stored is no longer a credential.
//
// It is not a replacement for a real secret manager. It is what makes a durable copy
// safe enough to exist, and a durable copy is what the platform turned out to need: the
// cache holding the only copy meant one Redis restart took every feed down at once.

// KeyBytes is the AES-256 key length this package requires.
const KeyBytes = 32

// ErrKeyRequired reports a sealer asked for without a key to seal with.
var ErrKeyRequired = errors.New("secrets: an encryption key is required")

// Sealer encrypts and decrypts secrets with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a sealer from a raw 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrKeyRequired, len(key), KeyBytes)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: build GCM: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// DecodeKey reads a base64 key, as it arrives from configuration.
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: it is not valid base64", ErrKeyRequired)
	}
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("%w: %d bytes decoded, want %d", ErrKeyRequired, len(key), KeyBytes)
	}
	return key, nil
}

// Seal encrypts a secret, returning base64 text safe to store as a column.
//
// The nonce is random per call and travels in front of the ciphertext, so the same secret
// sealed twice produces different text — a reader cannot tell that two feeds share a
// credential, which a deterministic scheme would leak.
func (s *Sealer) Seal(secret string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secrets: read nonce: %w", err)
	}

	sealed := s.aead.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts what Seal produced.
//
// A failure here means the stored text was written with a DIFFERENT KEY, or altered. It
// is reported rather than swallowed: silently treating it as "no secret" would rotate a
// working credential out of existence on the next write.
func (s *Sealer) Open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("secrets: stored secret is not valid base64: %w", err)
	}
	if len(raw) < s.aead.NonceSize() {
		return "", errors.New("secrets: stored secret is too short to hold a nonce")
	}

	nonce, ciphertext := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("secrets: stored secret could not be decrypted, which means "+
			"it was written with a different key: %w", err)
	}
	return string(plain), nil
}
