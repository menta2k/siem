package alerting

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CooldownStore is the ephemeral store suppression state lives in.
type CooldownStore interface {
	// SetNX records a key only if absent, reporting whether this caller set it.
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

// Cooldown suppresses repeat alerts for a rule within its cooldown period.
//
// Keyed by rule AND group values, not by rule alone. A rule grouped by host that is
// firing for one host must not silence the same rule for a different host — that would
// hide the second incident behind the first, which is the failure mode an operator
// would never think to look for.
//
// Redis-backed rather than in-memory because several processors run concurrently. An
// in-memory cooldown suppresses only the replica that fired, so N replicas send N
// copies of every alert.
type Cooldown struct {
	store CooldownStore
}

// NewCooldown constructs the suppressor.
func NewCooldown(store CooldownStore) *Cooldown {
	return &Cooldown{store: store}
}

// Allow reports whether an alert may fire, and claims the cooldown if so.
//
// Claim and check are ONE atomic operation (SETNX). Checking and then claiming would
// let two processors both observe an empty cooldown and both fire, which is precisely
// the duplicate this exists to prevent.
//
// A store failure returns the error rather than allowing the alert. Failing open would
// turn a Redis outage into an alert storm, at exactly the moment operators are least
// able to absorb one.
func (c *Cooldown) Allow(
	ctx context.Context, tenantID, ruleID uuid.UUID,
	groupValues map[string]string, cooldown time.Duration,
) (bool, error) {
	if cooldown <= 0 {
		// A rule with no cooldown fires every window. That is a valid choice for a
		// low-frequency rule, so it is honoured rather than overridden.
		return true, nil
	}

	key := CooldownKey(tenantID, ruleID, groupValues)
	claimed, err := c.store.SetNX(ctx, key, "1", cooldown)
	if err != nil {
		return false, fmt.Errorf("claim cooldown for rule %s: %w", ruleID, err)
	}
	return claimed, nil
}

// CooldownKey derives the suppression key for a rule and group.
//
// The group values are SORTED before hashing. Go map iteration is randomised, so an
// unsorted key would differ between two evaluations of the same group and the cooldown
// would never match itself — every window would fire.
//
// Hashed rather than concatenated because group values are attacker-influenced
// (a hostname, a client address) and could otherwise contain the separator, letting
// two distinct groups collide onto one cooldown and silence each other.
func CooldownKey(tenantID, ruleID uuid.UUID, groupValues map[string]string) string {
	if len(groupValues) == 0 {
		return fmt.Sprintf("alert:cooldown:%s:%s", tenantID, ruleID)
	}

	keys := make([]string, 0, len(groupValues))
	for key := range groupValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, key := range keys {
		// Length-prefixed so ("ab","c") and ("a","bc") cannot hash alike.
		//nolint:errcheck // hash.Hash.Write never returns an error
		fmt.Fprintf(h, "%d:%s=%d:%s;", len(key), key,
			len(groupValues[key]), groupValues[key])
	}

	return fmt.Sprintf("alert:cooldown:%s:%s:%x", tenantID, ruleID, h.Sum(nil)[:16])
}

// DescribeGroup renders group values for a human-readable alert summary.
func DescribeGroup(groupValues map[string]string) string {
	if len(groupValues) == 0 {
		return ""
	}

	keys := make([]string, 0, len(groupValues))
	for key := range groupValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, groupValues[key]))
	}
	return strings.Join(parts, " ")
}
