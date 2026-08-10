//go:build integration

package integration

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/test/support"
)

func validAuditRecord() audit.Record {
	actor := uuid.New()
	return audit.Record{
		ActorUserID: &actor,
		ActorEmail:  "admin@example.com",
		SourceIP:    net.ParseIP("203.0.113.10"),
		Action:      audit.ActionFeedUpdate,
		TargetType:  "feed",
		TargetID:    uuid.NewString(),
		BeforeValue: `{"enabled":true}`,
		AfterValue:  `{"enabled":false}`,
		Result:      audit.ResultSuccess,
	}
}

func auditRange() chdata.ListFilter {
	return chdata.ListFilter{
		From:  time.Now().Add(-time.Hour),
		To:    time.Now().Add(time.Hour),
		Limit: 1000,
	}
}

func TestAuditAppendAndRead(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "alpha")

	written, err := f.Audit.Append(ctx, validAuditRecord())
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	entries, err := f.Audit.List(ctx, auditRange())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List() returned %d entries, want 1", len(entries))
	}

	got := entries[0]
	if got.EntryID != written.EntryID {
		t.Errorf("EntryID = %v, want %v", got.EntryID, written.EntryID)
	}
	if got.TenantID != tenant.ID {
		t.Errorf("TenantID = %v, want %v", got.TenantID, tenant.ID)
	}
	if got.Action != audit.ActionFeedUpdate {
		t.Errorf("Action = %q, want %q", got.Action, audit.ActionFeedUpdate)
	}
	if got.BeforeValue != `{"enabled":true}` || got.AfterValue != `{"enabled":false}` {
		t.Errorf("before/after values were not round-tripped: %q -> %q",
			got.BeforeValue, got.AfterValue)
	}
	if got.EntryHash != written.EntryHash {
		t.Errorf("EntryHash changed through storage: %q -> %q", written.EntryHash, got.EntryHash)
	}
}

// The chain must survive a full round trip through ClickHouse. If storage alters any
// field — a truncated timestamp, a normalized IP — the rehash fails and the trail
// looks tampered with when it is not.
func TestAuditChainVerifiesAfterRoundTrip(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	for range 12 {
		if _, err := f.Audit.Append(ctx, validAuditRecord()); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	entries, err := f.Audit.List(ctx, auditRange())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 12 {
		t.Fatalf("List() returned %d entries, want 12", len(entries))
	}

	if err := audit.VerifyChain(entries); err != nil {
		t.Errorf("the chain does not verify after a storage round trip: %v", err)
	}
	err = f.Audit.VerifyChain(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("VerifyChain() = %v, want nil", err)
	}
}

// Each entry must link to the previous one, so a removal is detectable.
func TestAuditEntriesAreChainedInOrder(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	var written []audit.Entry
	for range 5 {
		e, err := f.Audit.Append(ctx, validAuditRecord())
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		written = append(written, e)
	}

	if written[0].PrevHash != audit.GenesisHash() {
		t.Errorf("first entry PrevHash = %q, want the genesis hash", written[0].PrevHash)
	}
	for i := 1; i < len(written); i++ {
		if written[i].PrevHash != written[i-1].EntryHash {
			t.Errorf("entry %d does not link to entry %d", i, i-1)
		}
	}
}

// Each tenant has its own chain, so one tenant's activity cannot break another's
// verification, and entry counts are not leaked across the boundary.
func TestAuditChainsArePerTenant(t *testing.T) {
	f := support.Shared(t)
	ctxA, _ := f.NewTenant(t, "alpha")
	ctxB, _ := f.NewTenant(t, "beta")

	// Interleave writes so a shared chain would visibly tangle.
	for range 4 {
		if _, err := f.Audit.Append(ctxA, validAuditRecord()); err != nil {
			t.Fatalf("append for A: %v", err)
		}
		if _, err := f.Audit.Append(ctxB, validAuditRecord()); err != nil {
			t.Fatalf("append for B: %v", err)
		}
	}

	entriesA, err := f.Audit.List(ctxA, auditRange())
	if err != nil {
		t.Fatalf("list for A: %v", err)
	}
	entriesB, err := f.Audit.List(ctxB, auditRange())
	if err != nil {
		t.Fatalf("list for B: %v", err)
	}

	if len(entriesA) != 4 || len(entriesB) != 4 {
		t.Fatalf("entry counts = A:%d B:%d, want 4 each", len(entriesA), len(entriesB))
	}
	if err := audit.VerifyChain(entriesA); err != nil {
		t.Errorf("tenant A's chain does not verify: %v", err)
	}
	if err := audit.VerifyChain(entriesB); err != nil {
		t.Errorf("tenant B's chain does not verify: %v", err)
	}
}

// Denied attempts are exactly what an investigator needs, so they must be recorded
// with the same fidelity as successes.
func TestAuditRecordsDeniedAttempts(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	record := audit.Record{
		ActorEmail: "attacker@example.com",
		SourceIP:   net.ParseIP("198.51.100.1"),
		Action:     audit.ActionLoginFailed,
		Result:     audit.ResultDenied,
		Detail:     "invalid password",
	}
	if _, err := f.Audit.Append(ctx, record); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	entries, err := f.Audit.List(ctx, chdata.ListFilter{
		From:   time.Now().Add(-time.Hour),
		To:     time.Now().Add(time.Hour),
		Action: string(audit.ActionLoginFailed),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List() returned %d entries, want the 1 denied attempt", len(entries))
	}
	if entries[0].Result != audit.ResultDenied {
		t.Errorf("Result = %q, want %q", entries[0].Result, audit.ResultDenied)
	}
	if entries[0].ActorEmail != "attacker@example.com" {
		t.Errorf("ActorEmail = %q, want the attempted identity preserved", entries[0].ActorEmail)
	}
}

func TestAuditFiltering(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	actions := []audit.Action{
		audit.ActionLogin, audit.ActionExport, audit.ActionRoleChange, audit.ActionExport,
	}
	for _, action := range actions {
		r := validAuditRecord()
		r.Action = action
		if _, err := f.Audit.Append(ctx, r); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	filtered, err := f.Audit.List(ctx, chdata.ListFilter{
		From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour),
		Action: string(audit.ActionExport), Limit: 10,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(filtered) != 2 {
		t.Errorf("filtering by export returned %d entries, want 2", len(filtered))
	}
	for _, e := range filtered {
		if e.Action != audit.ActionExport {
			t.Errorf("filter leaked action %q", e.Action)
		}
	}
}

// The time range must actually bound the query.
func TestAuditRespectsTimeRange(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	if _, err := f.Audit.Append(ctx, validAuditRecord()); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	past, err := f.Audit.List(ctx, chdata.ListFilter{
		From: time.Now().Add(-48 * time.Hour), To: time.Now().Add(-24 * time.Hour), Limit: 10,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(past) != 0 {
		t.Errorf("a range ending yesterday returned %d entries, want 0", len(past))
	}
}

// The repository must expose no way to modify or remove an entry (FR-035). Asserted
// by reflection so adding such a method fails the build rather than passing review.
func TestAuditRepoHasNoMutationMethods(t *testing.T) {
	repoType := reflect.TypeOf(&chdata.AuditRepo{})

	forbidden := []string{"Update", "Delete", "Remove", "Purge", "Truncate", "Set", "Replace"}
	for _, name := range forbidden {
		if _, found := repoType.MethodByName(name); found {
			t.Errorf("AuditRepo exposes %q; the audit trail must be append-only (FR-035)", name)
		}
	}

	for _, name := range []string{"Append", "List", "VerifyChain"} {
		if _, found := repoType.MethodByName(name); !found {
			t.Errorf("AuditRepo is missing the %q method", name)
		}
	}
}

func TestAuditDetailDoesNotCarryNewlines(t *testing.T) {
	f, ctx := support.SharedTenant(t, "alpha")

	r := validAuditRecord()
	r.Detail = "line one\nline two"
	entry, err := f.Audit.Append(ctx, r)
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	entries, err := f.Audit.List(ctx, auditRange())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries returned")
	}
	// Content is preserved verbatim — the trail records what happened, and sanitizing
	// belongs at the render boundary, not in the evidence.
	if !strings.Contains(entries[0].Detail, "line two") {
		t.Error("detail was truncated in storage")
	}
	if entries[0].EntryHash != entry.EntryHash {
		t.Error("hash changed through storage for multi-line detail")
	}
}

// The audit page's integrity indicator must report an intact chain as intact.
//
// This is the regression test for a defect the quickstart V5 run found on the live
// stack: ListAuditEntries never set ChainIntact, so the field kept its zero value and
// the page reported tampering on a chain that was provably whole. An indicator that
// always cries wolf is worse than none — operators learn to ignore it, and the one
// time it means something they will ignore it too.
func TestAuditListReportsAnIntactChainAsIntact(t *testing.T) {
	f, ctx := support.SharedTenant(t, "chainflag")

	for range 5 {
		if _, err := f.Audit.Append(ctx, validAuditRecord()); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	admin := service.NewAdminService(f.Users, f.Tenants, f.Audit, nil, nil, secrets.NewMemoryStore())
	resp, err := admin.ListAuditEntries(ctx, &pb.ListAuditEntriesRequest{
		Range: &pb.TimeRange{
			From: timestamppb.New(time.Now().Add(-time.Hour)),
			To:   timestamppb.New(time.Now().Add(time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("ListAuditEntries() error = %v", err)
	}

	if len(resp.GetEntries()) != 5 {
		t.Fatalf("returned %d entries, want 5", len(resp.GetEntries()))
	}
	if !resp.GetChainIntact() {
		t.Error("an untampered chain was reported as broken")
	}
}

// A range that begins mid-chain is the normal case for an audit page, and it must not
// be mistaken for tampering just because the earlier entries are out of view.
func TestAuditChainVerifiesOverAPartialRange(t *testing.T) {
	f, ctx := support.SharedTenant(t, "partialrange")

	for range 3 {
		if _, err := f.Audit.Append(ctx, validAuditRecord()); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	cut := time.Now()
	for range 3 {
		if _, err := f.Audit.Append(ctx, validAuditRecord()); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	// Only the entries after the cut — the chain's genesis is deliberately excluded.
	if err := f.Audit.VerifyChain(ctx, cut, time.Now().Add(time.Hour)); err != nil {
		t.Errorf("a range starting mid-chain was reported as broken: %v", err)
	}
}
