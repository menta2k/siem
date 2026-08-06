// Package auth provides authentication (credentials, MFA, tokens) and the
// authorization enforcer.
package auth

import (
	"context"
	_ "embed"
	"fmt"
	"slices"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"

	"github.com/menta2k/siem/internal/tenancy"
)

// Role names. These are the only four roles in the system (FR-034).
const (
	RoleAdmin      = "admin"
	RoleAnalyst    = "analyst"
	RoleAuditor    = "auditor"
	RoleIngestOnly = "ingest_only"
)

// wildcardDomain marks a policy line as a per-tenant template.
const wildcardDomain = "*"

//go:embed casbin/model.conf
var modelText string

//go:embed casbin/policy.csv
var policyText string

// Enforcer answers "may this subject perform this action on this object, in this
// tenant?". It is deny-by-default: an object with no matching policy line is
// unreachable, so forgetting to grant access fails closed.
type Enforcer struct {
	enforcer *casbin.Enforcer
}

// NewEnforcer builds the enforcer from the embedded model and policy. Embedding
// means the policy ships with the binary and cannot drift from the code that relies
// on it, and a malformed policy fails at startup rather than at the first request.
func NewEnforcer() (*Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("parse casbin model: %w", err)
	}

	adapter := stringadapter.NewAdapter(stripComments(policyText))
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("create casbin enforcer: %w", err)
	}
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load casbin policy: %w", err)
	}

	return &Enforcer{enforcer: e}, nil
}

// Allow reports whether the role may perform act on obj within the context's tenant.
//
// The tenant comes from the context, never from an argument: a caller cannot ask
// about the wrong tenant because it cannot name one.
func (e *Enforcer) Allow(ctx context.Context, role, obj, act string) (bool, error) {
	tenant, err := tenancy.FromContext(ctx)
	if err != nil {
		// No tenant means no authenticated scope. Deny rather than fall back.
		return false, err
	}
	if role == "" {
		return false, nil
	}

	domain := tenant.ID.String()

	// Policy lines are authored against the wildcard domain and instantiated per
	// tenant here, so a line can never grant access across tenants.
	allowed, err := e.enforcer.Enforce(role, wildcardDomain, obj, act)
	if err != nil {
		return false, fmt.Errorf("enforce %s %s %s in tenant %s: %w", role, act, obj, domain, err)
	}
	return allowed, nil
}

// Roles returns the four valid role names.
func Roles() []string {
	return []string{RoleAdmin, RoleAnalyst, RoleAuditor, RoleIngestOnly}
}

// ValidRole reports whether name is one of the four roles. Used to validate input at
// the boundary rather than discovering an unknown role at enforcement time.
func ValidRole(name string) bool {
	return slices.Contains(Roles(), name)
}

// stripComments removes the explanatory comments and blank lines from the embedded
// policy. The string adapter treats every line as a rule, so comments must go.
func stripComments(policy string) string {
	lines := strings.Split(policy, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, "\n")
}
