//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/asnowner"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/test/support"
)

var asnStamp = time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC)

func asnOwnerRepo(t *testing.T) (context.Context, *chdata.ASNOwnerRepo) {
	t.Helper()

	f := support.Shared(t)
	// The table is NOT tenant-scoped — who owns AS8866 is a fact about the internet —
	// so a tenant context exists only because the fixture's helpers expect one.
	ctx, _ := f.NewTenant(t, "asn-owners")
	return ctx, chdata.NewASNOwnerRepo(f.ClickHouse)
}

func TestASNOwnersResolveWhatWasStored(t *testing.T) {
	ctx, repo := asnOwnerRepo(t)

	err := repo.Replace(ctx, []chdata.ASNOwner{
		{ASN: 8866, Name: "VIVACOM-AS", Country: "BG"},
		{ASN: 13335, Name: "CLOUDFLARENET", Country: "US"},
	}, asnStamp)
	if err != nil {
		t.Fatalf("Replace(): %v", err)
	}
	support.Shared(t).Sync(t, "asn_owners")

	names, err := repo.NamesFor(ctx, []uint32{8866, 13335, 64512})
	if err != nil {
		t.Fatalf("NamesFor(): %v", err)
	}

	if names[8866] != "VIVACOM-AS" || names[13335] != "CLOUDFLARENET" {
		t.Errorf("names = %+v, want both networks", names)
	}
	// An ASN the published table does not list resolves to nothing rather than to an
	// error: the console shows the bare number, as it did before names existed.
	if _, present := names[64512]; present {
		t.Errorf("an unknown ASN was named: %+v", names)
	}
}

// The table is a ReplacingMergeTree keyed on the AS number, which is what lets a refresh
// insert the whole snapshot without truncating first — no window in which a query sees
// an empty table.
func TestASNOwnersKeepOneRowPerNetworkAcrossRefreshes(t *testing.T) {
	ctx, repo := asnOwnerRepo(t)
	f := support.Shared(t)

	for i := range 3 {
		// The third pass renames the network, as a real re-registration would.
		name := "OLD-NAME"
		if i == 2 {
			name = "NEW-NAME"
		}
		err := repo.Replace(ctx,
			[]chdata.ASNOwner{{ASN: 65001, Name: name, Country: "BG"}},
			asnStamp.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatalf("Replace(%d): %v", i, err)
		}
	}
	f.Sync(t, "asn_owners")

	names, err := repo.NamesFor(ctx, []uint32{65001})
	if err != nil {
		t.Fatalf("NamesFor(): %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("got %d rows for one network, want 1: %+v", len(names), names)
	}
	if names[65001] != "NEW-NAME" {
		t.Errorf("name = %q, want the newest one", names[65001])
	}
}

// A download that yielded nothing is a failed download. Writing it would be
// indistinguishable from the upstream having deleted the internet.
func TestASNOwnersRefuseAnEmptySnapshot(t *testing.T) {
	ctx, repo := asnOwnerRepo(t)

	if err := repo.Replace(ctx, nil, asnStamp); err == nil {
		t.Error("Replace() accepted an empty snapshot")
	}
}

// The resolver is what the read paths hold. Driving it against the real table proves
// the caching layer and the query agree about what "unknown" means.
func TestResolverNamesNetworksFromTheStoredTable(t *testing.T) {
	ctx, repo := asnOwnerRepo(t)

	err := repo.Replace(ctx,
		[]chdata.ASNOwner{{ASN: 29244, Name: "BTC-NET", Country: "BG"}}, asnStamp)
	if err != nil {
		t.Fatalf("Replace(): %v", err)
	}
	support.Shared(t).Sync(t, "asn_owners")

	resolver := asnowner.NewResolver(repo, time.Minute)

	if got := resolver.Name(ctx, 29244); got != "BTC-NET" {
		t.Errorf("Name(29244) = %q, want BTC-NET", got)
	}
	if got := resolver.Name(ctx, 64599); got != "" {
		t.Errorf("Name(64599) = %q, want empty for an unlisted network", got)
	}
}
