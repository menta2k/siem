// Package audit records privileged actions in an append-only, tamper-evident trail.
//
// Two properties define this package:
//
//  1. Append-only. There is no Update and no Delete method, anywhere, deliberately.
//     The audit trail is the record of what was done to the system, so the system
//     must not be able to rewrite it.
//  2. Tamper-evident. Entries are hash-chained per tenant per day, so removing or
//     editing an entry breaks the chain and is detectable by walking it.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Action names every privileged operation that must be recorded (FR-035).
type Action string

// The complete set of audited actions. Adding a privileged operation without adding
// it here means that operation leaves no trail, so this list is the checklist a
// reviewer walks when a new admin endpoint appears.
const (
	ActionLogin                     Action = "login"
	ActionLoginFailed               Action = "login_failed"
	ActionLogout                    Action = "logout"
	ActionRoleChange                Action = "role_change"
	ActionUserCreate                Action = "user_create"
	ActionUserDelete                Action = "user_delete"
	ActionFeedCreate                Action = "feed_create"
	ActionFeedUpdate                Action = "feed_update"
	ActionFeedDelete                Action = "feed_delete"
	ActionCorrelationSettingsChange Action = "correlation_settings_change"
	ActionRetentionChange           Action = "retention_change"
	ActionRuleCreate                Action = "rule_create"
	ActionRuleUpdate                Action = "rule_update"
	ActionRuleDelete                Action = "rule_delete"
	ActionAlertStateChange          Action = "alert_state_change"
	ActionExport                    Action = "export"
	ActionPurge                     Action = "purge"
)

// Result records whether the action succeeded or was refused. Denied attempts are
// recorded too: a rejected privilege escalation is exactly what an investigator needs
// to see.
type Result string

// The two outcomes an audited action can have.
const (
	ResultSuccess Result = "success"
	ResultDenied  Result = "denied"
)

// genesisHash seeds a tenant's chain for its first entry of a day.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one immutable audit record.
type Entry struct {
	TenantID    uuid.UUID
	EntryID     uuid.UUID
	OccurredAt  time.Time
	ActorUserID *uuid.UUID
	ActorEmail  string
	SourceIP    net.IP
	Action      Action
	TargetType  string
	TargetID    string
	BeforeValue string
	AfterValue  string
	Result      Result
	Detail      string

	PrevHash  string
	EntryHash string
}

// Record is the caller-supplied part of an entry. The writer fills in the identity,
// timestamp, and chain fields, so a caller cannot forge them.
type Record struct {
	ActorUserID *uuid.UUID
	ActorEmail  string
	SourceIP    net.IP
	Action      Action
	TargetType  string
	TargetID    string
	BeforeValue string
	AfterValue  string
	Result      Result
	Detail      string
}

// Validate checks a record before it is chained and written. An audit entry that
// cannot identify its actor or its action is worse than useless — it creates the
// appearance of a trail without the substance.
func (r Record) Validate() error {
	if r.Action == "" {
		return fmt.Errorf("audit: action is required")
	}
	if r.Result != ResultSuccess && r.Result != ResultDenied {
		return fmt.Errorf("audit: result must be %q or %q, got %q", ResultSuccess, ResultDenied, r.Result)
	}
	// A failed login has no known user id but does have an attempted identity, so
	// the email is required even when the actor id is not.
	if r.ActorEmail == "" && r.ActorUserID == nil {
		return fmt.Errorf("audit: an actor email or user id is required for action %q", r.Action)
	}
	return nil
}

// computeHash derives an entry's hash from its content and the previous entry's hash.
//
// Every field that matters is included, so altering any of them changes the hash and
// breaks the chain from that point onward. Fields are length-prefixed to prevent a
// concatenation ambiguity where moving a character between adjacent fields would
// leave the digest unchanged.
func computeHash(e Entry) string {
	h := sha256.New()

	actorID := ""
	if e.ActorUserID != nil {
		actorID = e.ActorUserID.String()
	}
	sourceIP := ""
	if e.SourceIP != nil {
		sourceIP = e.SourceIP.String()
	}

	fields := []string{
		e.PrevHash,
		e.TenantID.String(),
		e.EntryID.String(),
		e.OccurredAt.UTC().Format(time.RFC3339Nano),
		actorID,
		e.ActorEmail,
		sourceIP,
		string(e.Action),
		e.TargetType,
		e.TargetID,
		e.BeforeValue,
		e.AfterValue,
		string(e.Result),
		e.Detail,
	}
	for _, f := range fields {
		// Length prefix removes the ambiguity between ("ab","c") and ("a","bc").
		// hash.Hash.Write never returns an error, so this cannot fail.
		fmt.Fprintf(h, "%d:%s|", len(f), f) //nolint:errcheck // hash.Hash.Write never errors
	}

	return hex.EncodeToString(h.Sum(nil))
}

// Chain links a record into a tenant's chain, returning a complete entry. It does not
// mutate the input: the returned Entry is a new value.
func Chain(tenantID uuid.UUID, prevHash string, occurredAt time.Time, r Record) (Entry, error) {
	if err := r.Validate(); err != nil {
		return Entry{}, err
	}
	if prevHash == "" {
		prevHash = genesisHash
	}

	entry := Entry{
		TenantID: tenantID,
		EntryID:  uuid.New(),
		// Truncated to milliseconds to match the DateTime64(3) storage precision.
		// Hashing a nanosecond value that storage then rounds would make every entry
		// fail verification after a round trip — the chain must be computed over the
		// value as it will actually be persisted, not as it happens to be in memory.
		OccurredAt:  occurredAt.UTC().Truncate(time.Millisecond),
		ActorUserID: r.ActorUserID,
		ActorEmail:  strings.ToLower(strings.TrimSpace(r.ActorEmail)),
		SourceIP:    r.SourceIP,
		Action:      r.Action,
		TargetType:  r.TargetType,
		TargetID:    r.TargetID,
		BeforeValue: r.BeforeValue,
		AfterValue:  r.AfterValue,
		Result:      r.Result,
		Detail:      r.Detail,
		PrevHash:    prevHash,
	}
	entry.EntryHash = computeHash(entry)
	return entry, nil
}

// VerifyChain walks entries in order and reports the first break.
//
// A break means an entry was altered or removed after the fact. This is the check
// behind the audit page's integrity indicator and the quarterly sampling review.
func VerifyChain(entries []Entry) error {
	expectedPrev := genesisHash

	for i, e := range entries {
		if e.PrevHash != expectedPrev {
			return fmt.Errorf(
				"audit chain broken at index %d (entry %s): prev_hash is %s but the "+
					"preceding entry hashes to %s — an entry was altered or removed",
				i, e.EntryID, e.PrevHash, expectedPrev)
		}
		if got := computeHash(e); got != e.EntryHash {
			return fmt.Errorf(
				"audit entry %s at index %d has been modified: stored hash %s "+
					"does not match its content (%s)",
				e.EntryID, i, e.EntryHash, got)
		}
		expectedPrev = e.EntryHash
	}
	return nil
}

// VerifyRange checks a slice of consecutive entries that may begin mid-chain.
//
// It is what an audit page needs. VerifyChain requires the slice to start at the
// tenant's very first entry, so using it to check a time range would report tampering
// for every range that does not reach back to the beginning — an integrity indicator
// that cries wolf is worse than none, because operators learn to ignore it.
//
// The two things a reader can actually check without the earlier entries are still
// checked here, and they are the two that matter: every entry still hashes to its own
// content, and each entry still links to the one before it. An alteration or a removal
// inside the range breaks one of them.
func VerifyRange(entries []Entry) error {
	for i, e := range entries {
		if got := computeHash(e); got != e.EntryHash {
			return fmt.Errorf(
				"audit entry %s at index %d has been modified: stored hash %s "+
					"does not match its content (%s)",
				e.EntryID, i, e.EntryHash, got)
		}
		if i == 0 {
			continue
		}
		if e.PrevHash != entries[i-1].EntryHash {
			return fmt.Errorf(
				"audit chain broken at index %d (entry %s): prev_hash is %s but the "+
					"preceding entry hashes to %s — an entry was altered or removed",
				i, e.EntryID, e.PrevHash, entries[i-1].EntryHash)
		}
	}
	return nil
}

// GenesisHash exposes the chain seed for repositories starting a new tenant-day.
func GenesisHash() string { return genesisHash }
