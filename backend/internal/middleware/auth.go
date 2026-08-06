package middleware

import (
	"context"
	"strings"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/auth"
	"github.com/menta2k/siem/internal/tenancy"
)

// TokenParser validates an access token.
type TokenParser interface {
	ParseAccess(token string) (*auth.Claims, error)
}

// Authorizer decides whether a role may perform an operation.
type Authorizer interface {
	Allow(ctx context.Context, role, obj, act string) (bool, error)
}

// TenantLoader resolves the tenant named in a token.
//
// The token carries a tenant id, but a suspended tenant's outstanding tokens stay
// cryptographically valid until they expire. Re-reading the tenant on each request is
// what makes a suspension take effect immediately rather than up to an access-token
// lifetime later.
// The interface is narrow and free of storage types on purpose: internal/query
// imports this package, so a dependency on the ClickHouse package here would close a
// cycle. The adapter that satisfies it lives beside the server wiring.
type TenantLoader interface {
	Active(ctx context.Context, tenantID uuid.UUID) (name string, active bool, err error)
}

// publicOperations are reachable without a token.
//
// An explicit set, not a prefix. A prefix rule would silently expose every future
// route that happened to start with the same path, which is the same deny-by-default
// property the Casbin policy is written to preserve.
var publicOperations = map[string]bool{
	"/siem.v1.Auth/Login":        true,
	"/siem.v1.Auth/RefreshToken": true,
	"/siem.v1.Auth/VerifyMFA":    true,
}

// Auth authenticates the caller, scopes the request to their tenant, and enforces the
// role policy.
//
// The three steps are one middleware because they are one decision and the ordering
// between them is load-bearing: the tenant must be in the context before the policy is
// consulted, since a policy line is instantiated per tenant and cannot be evaluated
// without one.
func Auth(
	parser TokenParser, authz Authorizer, tenants TenantLoader, log Logger,
) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return nil, Internal()
			}
			if publicOperations[tr.Operation()] {
				return handler(ctx, req)
			}

			claims, err := authenticate(parser, tr)
			if err != nil {
				return nil, err
			}

			ctx, err = scopeToTenant(ctx, claims, tenants)
			if err != nil {
				return nil, err
			}
			ctx = auth.WithClaims(ctx, claims)

			if err := authorize(ctx, authz, claims, tr, log); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}
	}
}

// authenticate extracts and validates the bearer token.
func authenticate(parser TokenParser, tr transport.Transporter) (*auth.Claims, error) {
	header := tr.RequestHeader().Get("Authorization")
	token, found := strings.CutPrefix(header, "Bearer ")
	if !found || strings.TrimSpace(token) == "" {
		return nil, Unauthenticated("a bearer token is required")
	}

	claims, err := parser.ParseAccess(strings.TrimSpace(token))
	if err != nil {
		// The parse failure is not echoed back. "signature is invalid" versus "token is
		// expired" tells an attacker which half of a forgery attempt worked.
		return nil, Unauthenticated("the access token is not valid")
	}
	return claims, nil
}

// scopeToTenant puts the caller's tenant on the context after confirming it is active.
func scopeToTenant(
	ctx context.Context, claims *auth.Claims, tenants TenantLoader,
) (context.Context, error) {
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, Unauthenticated("the access token is not valid")
	}

	name, active, err := tenants.Active(ctx, tenantID)
	if err != nil {
		return nil, Internal().WithCause(err)
	}
	if !active {
		return nil, TenantSuspended()
	}

	return tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenantID, Name: name}), nil
}

// authorize consults the policy for this route.
func authorize(
	ctx context.Context, authz Authorizer, claims *auth.Claims,
	tr transport.Transporter, log Logger,
) error {
	obj, act := requestTarget(tr)

	allowed, err := authz.Allow(ctx, claims.Role, obj, act)
	if err != nil {
		return Internal().WithCause(err)
	}
	if !allowed {
		// Logged because a denied request is what an investigator looks for: a rejected
		// privilege escalation leaves no other trace.
		log.Warn(ctx, "authorization denied",
			"role", claims.Role, "object", obj, "action", act, "actor", claims.Email)
		return PermissionDenied()
	}
	return nil
}

// requestTarget returns the path and method the policy is written against.
//
// The policy is authored in terms of HTTP routes rather than gRPC operation names,
// because the routes are what an operator reviewing the policy sees in the API
// documentation and in their access logs.
//
// The PATH TEMPLATE is used, not the concrete path: the policy matches
// `/api/v1/feeds/:id`, and passing the substituted path would compare a real UUID
// against a placeholder and deny every parameterised route.
func requestTarget(tr transport.Transporter) (string, string) {
	ht, ok := tr.(khttp.Transporter)
	if !ok {
		// Not an HTTP request. Nothing in this service is reachable another way, so
		// falling back to a permissive default would be inventing an unpoliced path;
		// the operation name matches no policy line and is therefore denied.
		return tr.Operation(), ""
	}
	return normalizePathTemplate(ht.PathTemplate()), ht.Request().Method
}

// normalizePathTemplate converts Kratos's `{id}` placeholders into the `:id` form the
// Casbin keyMatch2 policy is written in.
//
// Without this every parameterised route is denied, and the failure looks like a
// permissions bug rather than a syntax mismatch — the policy line is right there and
// appears to match.
func normalizePathTemplate(template string) string {
	if !strings.ContainsRune(template, '{') {
		return template
	}

	var b strings.Builder
	b.Grow(len(template))
	for i := 0; i < len(template); i++ {
		switch template[i] {
		case '{':
			b.WriteByte(':')
		case '}':
			// Dropped: the closing brace has no equivalent in the `:param` form.
		default:
			b.WriteByte(template[i])
		}
	}
	return b.String()
}
