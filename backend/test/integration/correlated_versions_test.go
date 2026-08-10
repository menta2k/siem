//go:build integration

package integration

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

// WHY THIS SUITE EXISTS. Versions and ByIDs are the closer's two reads, they run on the
// hot path of every tick, and neither used to be covered by anything but a fake store —
// which returns whatever it was handed and therefore cannot fail when the SQL is wrong.
//
// Both queries pick the winning row out of a ReplacingMergeTree WITHOUT using FINAL,
// which is the whole point: FINAL merges parts to answer, and these do not need it.
// Whether that substitution is actually correct is a property of the engine, not of this
// code, so a real server is the only thing that can answer it. An unmerged read is also
// the NORMAL case here rather than a rare one — the closer reads records it wrote seconds
// earlier, long before ClickHouse has merged anything.

// versionedRecord builds one version of a correlated record, distinguishable by the
// fields the merge path actually reads back.
func versionedRecord(
	tenantID, correlationID uuid.UUID, at time.Time, version uint64, vendorList []string,
) chdata.CorrelatedRequest {
	return chdata.CorrelatedRequest{
		TenantID:       tenantID,
		CorrelationID:  correlationID,
		WindowStart:    at,
		FirstEventTime: at,
		LastEventTime:  at.Add(time.Duration(version) * time.Second),
		Vendors:        vendorList,
		VendorCount:    uint8(len(vendorList)),
		EventIDs:       vendorList,
		ClientIP:       net.ParseIP("203.0.113.7"),
		RequestHost:    "versions.example.com",
		RequestPath:    "/checkout",
		RequestMethod:  "GET",
		Verdicts:       map[string]string{vendors.Cloudflare: vendors.VerdictAllowed},
		RuleIDs:        map[string]string{},
		Scores:         map[string]float32{},
		JoinSignals:    []string{"vendor_request_id"},
		JoinTier:       1,
		Confidence:     "high",
		Version:        version,
		Amended:        version > 1,
	}
}

// Versions must report the HIGHEST version of an amended record. If it reported a
// superseded one the closer would write the next amendment at a version that already
// exists, and the record would stop advancing — every later amendment silently lost
// behind the one already stored at that version.
func TestVersionsReportsTheLatestOfAnAmendedRecord(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "correlated-versions")

	repo := chdata.NewCorrelatedRepo(f.ClickHouse)
	id := uuid.New()
	at := time.Now().UTC().Truncate(time.Second)

	// Three separate inserts, so the versions land in THREE PARTS. A single insert would
	// put them in one part and prove much less: the risk being tested is precisely that
	// an unmerged read across parts returns a stale row.
	for version := uint64(1); version <= 3; version++ {
		record := versionedRecord(tenant.ID, id, at, version,
			[]string{vendors.Cloudflare, vendors.F5, vendors.Nginx}[:version])
		if err := repo.Insert(ctx, []chdata.CorrelatedRequest{record}); err != nil {
			t.Fatalf("Insert(version %d): %v", version, err)
		}
	}

	versions, err := repo.Versions(ctx, []uuid.UUID{id})
	if err != nil {
		t.Fatalf("Versions(): %v", err)
	}

	got, ok := versions[id]
	if !ok {
		t.Fatal("the record is absent, which the closer reads as 'never stored' — it " +
			"would write a second record at version 1 beside the one already there")
	}
	if got != 3 {
		t.Errorf("version = %d, want 3; a stale version makes every later amendment "+
			"collide with a row that already exists", got)
	}
}

// An id that was never stored must be ABSENT, not zero. Absence is how the closer says
// "this is a new record", and a zero would be read as an existing record at version 0.
func TestVersionsOmitsIdsThatWereNeverStored(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "correlated-versions-absent")

	versions, err := chdata.NewCorrelatedRepo(f.ClickHouse).
		Versions(ctx, []uuid.UUID{uuid.New()})
	if err != nil {
		t.Fatalf("Versions(): %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("got %v, want an empty map for an id with no record", versions)
	}
}

// ByIDs must return the CONTENTS of the winning version. This is the one that would do
// real damage: the record it returns is what mergeRecords folds the fresh window into,
// so a superseded copy would resurrect vendors and verdicts that a later amendment had
// already corrected, and write them back as current.
func TestByIDsReturnsTheWinningVersionNotASupersededOne(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "correlated-by-ids")

	repo := chdata.NewCorrelatedRepo(f.ClickHouse)
	id := uuid.New()
	at := time.Now().UTC().Truncate(time.Second)

	first := versionedRecord(tenant.ID, id, at, 1, []string{vendors.Cloudflare})
	if err := repo.Insert(ctx, []chdata.CorrelatedRequest{first}); err != nil {
		t.Fatalf("Insert(version 1): %v", err)
	}

	second := versionedRecord(tenant.ID, id, at, 2,
		[]string{vendors.Cloudflare, vendors.F5, vendors.Nginx})
	second.Verdicts = map[string]string{
		vendors.Cloudflare: vendors.VerdictAllowed,
		vendors.F5:         vendors.VerdictBlocked,
	}
	second.HasDisagreement = true
	if err := repo.Insert(ctx, []chdata.CorrelatedRequest{second}); err != nil {
		t.Fatalf("Insert(version 2): %v", err)
	}

	records, err := repo.ByIDs(ctx, []uuid.UUID{id})
	if err != nil {
		t.Fatalf("ByIDs(): %v", err)
	}

	// Exactly one row per id. Without the de-duplication this returns every version, and
	// which one survives into the map is decided by row order — a coin toss.
	if len(records) != 1 {
		t.Fatalf("got %d records for one id, want 1: %+v", len(records), records)
	}

	got := records[id]
	if got.Version != 2 {
		t.Fatalf("version = %d, want 2 — ByIDs returned a superseded row", got.Version)
	}
	if got.VendorCount != 3 || len(got.Vendors) != 3 {
		t.Errorf("vendors = %v (count %d), want all three from version 2",
			got.Vendors, got.VendorCount)
	}
	if !got.HasDisagreement {
		t.Error("the disagreement recorded in version 2 was not returned; the merge " +
			"would write the record back as though the vendors still agreed")
	}
	if got.Verdicts[vendors.F5] != vendors.VerdictBlocked {
		t.Errorf("f5 verdict = %q, want the blocked one from version 2",
			got.Verdicts[vendors.F5])
	}
}

// One call, many ids, mixed existence. This is the shape the closer actually issues, and
// the de-duplication has to apply PER ID rather than to the result as a whole.
func TestByIDsResolvesEachIdIndependently(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "correlated-by-ids-many")

	repo := chdata.NewCorrelatedRepo(f.ClickHouse)
	at := time.Now().UTC().Truncate(time.Second)

	amended, single, absent := uuid.New(), uuid.New(), uuid.New()

	for version := uint64(1); version <= 2; version++ {
		record := versionedRecord(tenant.ID, amended, at, version,
			[]string{vendors.Cloudflare, vendors.F5}[:version])
		if err := repo.Insert(ctx, []chdata.CorrelatedRequest{record}); err != nil {
			t.Fatalf("Insert(amended version %d): %v", version, err)
		}
	}
	if err := repo.Insert(ctx, []chdata.CorrelatedRequest{
		versionedRecord(tenant.ID, single, at, 1, []string{vendors.Nginx}),
	}); err != nil {
		t.Fatalf("Insert(single): %v", err)
	}

	records, err := repo.ByIDs(ctx, []uuid.UUID{amended, single, absent})
	if err != nil {
		t.Fatalf("ByIDs(): %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 — the third id has none", len(records))
	}
	if got := records[amended].Version; got != 2 {
		t.Errorf("amended record came back at version %d, want 2", got)
	}
	if got := records[single].Version; got != 1 {
		t.Errorf("single record came back at version %d, want 1", got)
	}
	if _, present := records[absent]; present {
		t.Error("an id with no record must be absent from the map, not zero-valued")
	}
}
