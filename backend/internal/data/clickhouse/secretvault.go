package clickhouse

import (
	"context"

	"github.com/menta2k/siem/internal/secrets"
)

// Adapting the ClickHouse client to the tiny surface the durable secret store needs.
//
// The store deliberately does not import this package: it holds the one thing in the
// system that must be storable somewhere else entirely, and a direct dependency on the
// analytical client would make that swap a rewrite rather than a wiring change.

// SecretVault exposes the client as the durable store's database.
type SecretVault struct {
	client *Client
}

// NewSecretVault wraps the client.
func NewSecretVault(client *Client) *SecretVault { return &SecretVault{client: client} }

// Query runs a read, returning rows behind the store's own interface.
func (v *SecretVault) Query(
	ctx context.Context, query string, args ...any,
) (secrets.Rows, error) {
	return v.client.Query(ctx, query, args...)
}

// Exec runs a write.
func (v *SecretVault) Exec(ctx context.Context, query string, args ...any) error {
	return v.client.Exec(ctx, query, args...)
}
