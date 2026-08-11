//go:build integration

package integration

import (
	"testing"

	"github.com/menta2k/siem/test/support"
)

// THE CLASS OF BUG THIS COLUMN EXISTS TO CLOSE.
//
// An event's vendor and the vendor whose feed delivered it are different facts, and the
// platform stored only the first. A DataDome verdict is normalized out of a Cloudflare
// Worker's log of its own call to the DataDome API: attributed to datadome, delivered by
// cloudflare, raw payload filed under cloudflare. Every read path that needed the second
// fact had to infer it, and in one session four of them inferred it wrongly — the payload
// lookup matched nothing, the field rebuild parsed with the wrong adapter, a correlated
// record appeared to be missing a raw event, and the lookup could not use the sort key.
//
// These assert the fact is now RECORDED rather than inferred. They run against real
// ClickHouse because the column's default on pre-existing rows is part of the contract.

// Every event written from now on records which feed delivered it.
func TestNormalizedEventsRecordTheDeliveringVendor(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "source-vendor")

	rows, err := f.ClickHouse.Query(ctx,
		"SELECT type FROM system.columns WHERE database = ? AND table = ? AND name = ?",
		f.Database, "normalized_events", "source_vendor")
	if err != nil {
		t.Fatalf("read system.columns: %v", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		t.Fatal("normalized_events has no source_vendor column; migration 0012 did not " +
			"apply, and every read path is back to guessing which feed delivered an event")
	}
	var columnType string
	if err := rows.Scan(&columnType); err != nil {
		t.Fatalf("scan column type: %v", err)
	}
	// LowCardinality because a deployment has a handful of vendors and this column is read
	// on the detail path; a plain String would store the same short word per row.
	if columnType != "LowCardinality(String)" {
		t.Errorf("source_vendor is %s, want LowCardinality(String)", columnType)
	}
}

// Rows written before the column existed must read as EMPTY, not as a guess.
//
// The default is what makes the rollout safe: a reader seeing "" falls back to the slower
// unseekable lookup, whereas a default of the event's own vendor would silently reintroduce
// the exact wrong assumption for every historical row.
func TestTheDeliveringVendorDefaultsToEmptyNotToTheEventsVendor(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "source-vendor-default")

	rows, err := f.ClickHouse.Query(ctx,
		"SELECT default_kind, default_expression FROM system.columns "+
			"WHERE database = ? AND table = ? AND name = ?",
		f.Database, "normalized_events", "source_vendor")
	if err != nil {
		t.Fatalf("read system.columns: %v", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		t.Fatal("source_vendor column is missing")
	}
	var kind, expression string
	if err := rows.Scan(&kind, &expression); err != nil {
		t.Fatalf("scan default: %v", err)
	}

	// An empty string default renders as DEFAULT '' — anything naming another column
	// would mean a historical row claims a delivering vendor nobody recorded.
	if expression != "''" && expression != "" {
		t.Errorf("source_vendor defaults to %q (%s); it must default to an empty string so "+
			"a row written before the column reads as UNKNOWN rather than as a guess",
			expression, kind)
	}
}
