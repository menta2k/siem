//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

var searchBase = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func searchRange() query.TimeRange {
	return query.TimeRange{From: searchBase.Add(-time.Hour), To: searchBase.Add(time.Hour)}
}

// searchFor runs a filtered search and returns the matching event ids.
func searchFor(
	ctx context.Context, t *testing.T, repo *chdata.SearchRepo, build func(*query.Builder),
) []string {
	t.Helper()

	b := query.NewBuilder(query.EventsTable)
	build(b)
	conditions, args, err := b.Conditions()
	if err != nil {
		t.Fatalf("build conditions: %v", err)
	}

	page, err := repo.SearchEvents(ctx, chdata.EventQuery{
		Range: searchRange(), Conditions: conditions, Args: args, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}

	ids := make([]string, 0, len(page.Items))
	for _, item := range page.Items {
		ids = append(ids, item.EventID)
	}
	return ids
}

// seedSearchCorpus writes a small cross-vendor dataset with distinguishable rows.
func seedSearchCorpus(ctx context.Context, t *testing.T, f *support.Fixture, tenantID [16]byte) {
	t.Helper()

	score := func(v float32) *float32 { return &v }

	events := []chdata.NormalizedEvent{
		{
			EventID: "cf-blocked", Vendor: vendors.Cloudflare,
			ClientIP: net.ParseIP("203.0.113.10"), ClientCountry: "DE", ClientASN: 64512,
			RequestHost: "shop.example.com", RequestPath: "/checkout",
			RequestMethod: "POST", HTTPStatus: 403,
			UserAgent: "curl/8.0", Verdict: vendors.VerdictBlocked,
			RuleID: "waf-sqli", Score: score(0.9), ScoreKind: vendors.ScoreKindBot,
		},
		{
			EventID: "f5-allowed", Vendor: vendors.F5,
			ClientIP: net.ParseIP("198.51.100.7"), ClientCountry: "FR", ClientASN: 64513,
			RequestHost: "api.example.com", RequestPath: "/v1/orders",
			RequestMethod: "GET", HTTPStatus: 200,
			UserAgent: "Mozilla/5.0", Verdict: vendors.VerdictAllowed,
			RuleID: "", Score: score(0.1), ScoreKind: vendors.ScoreKindBot,
		},
		{
			EventID: "dd-challenged", Vendor: vendors.DataDome,
			ClientIP: net.ParseIP("203.0.113.10"), ClientCountry: "DE", ClientASN: 64512,
			RequestHost: "shop.example.com", RequestPath: "/login",
			RequestMethod: "POST", HTTPStatus: 401,
			UserAgent: "python-requests/2.31", Verdict: vendors.VerdictChallenged,
			RuleID: "bot-1", Score: score(0.75), ScoreKind: vendors.ScoreKindBot,
		},
	}

	for i := range events {
		events[i].TenantID = tenantID
		events[i].EventTime = searchBase.Add(time.Duration(i) * time.Second)
		events[i].ReceivedAt = events[i].EventTime
		events[i].IngestVersion = 1
	}

	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(ctx, events); err != nil {
		t.Fatalf("seed search corpus: %v", err)
	}
	f.Sync(t, "normalized_events")
}

// Every filter an analyst reaches for during an incident, against real storage. A
// filter that silently matches nothing is indistinguishable from an absence of
// attacks, which is the most expensive way for a search to be wrong.
func TestCrossVendorFilters(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-filters")
	seedSearchCorpus(ctx, t, f, tenant.ID)

	repo := chdata.NewSearchRepo(f.ClickHouse)

	cases := map[string]struct {
		build func(*query.Builder)
		want  []string
	}{
		"by client ip": {
			build: func(b *query.Builder) { b.Where("client_ip", query.OpEqual, "203.0.113.10") },
			want:  []string{"cf-blocked", "dd-challenged"},
		},
		"by host": {
			build: func(b *query.Builder) {
				b.Where("request_host", query.OpEqual, "api.example.com")
			},
			want: []string{"f5-allowed"},
		},
		"by path": {
			build: func(b *query.Builder) { b.Where("request_path", query.OpEqual, "/login") },
			want:  []string{"dd-challenged"},
		},
		"by vendor": {
			build: func(b *query.Builder) {
				b.Where("vendor", query.OpIn, []string{vendors.F5, vendors.DataDome})
			},
			want: []string{"f5-allowed", "dd-challenged"},
		},
		"by verdict": {
			build: func(b *query.Builder) {
				b.Where("verdict", query.OpEqual, vendors.VerdictBlocked)
			},
			want: []string{"cf-blocked"},
		},
		"by rule": {
			build: func(b *query.Builder) { b.Where("rule_id", query.OpEqual, "waf-sqli") },
			want:  []string{"cf-blocked"},
		},
		"by minimum score": {
			build: func(b *query.Builder) {
				b.Where("score", query.OpGreaterEqual, float32(0.7))
			},
			want: []string{"cf-blocked", "dd-challenged"},
		},
		"by score range": {
			build: func(b *query.Builder) {
				b.Where("score", query.OpGreaterEqual, float32(0.7))
				b.Where("score", query.OpLessEqual, float32(0.8))
			},
			want: []string{"dd-challenged"},
		},
		"by country": {
			build: func(b *query.Builder) { b.Where("country", query.OpEqual, "FR") },
			want:  []string{"f5-allowed"},
		},
		"by asn": {
			build: func(b *query.Builder) { b.Where("client_asn", query.OpEqual, uint32(64513)) },
			want:  []string{"f5-allowed"},
		},
		"by method": {
			build: func(b *query.Builder) { b.Where("request_method", query.OpEqual, "POST") },
			want:  []string{"cf-blocked", "dd-challenged"},
		},
		"by http status": {
			build: func(b *query.Builder) { b.Where("http_status", query.OpEqual, uint16(403)) },
			want:  []string{"cf-blocked"},
		},
		"combined": {
			build: func(b *query.Builder) {
				b.Where("client_ip", query.OpEqual, "203.0.113.10")
				b.Where("request_method", query.OpEqual, "POST")
				b.Where("verdict", query.OpEqual, vendors.VerdictChallenged)
			},
			want: []string{"dd-challenged"},
		},
		"matching nothing": {
			build: func(b *query.Builder) {
				b.Where("request_host", query.OpEqual, "nowhere.example.com")
			},
			want: []string{},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := searchFor(ctx, t, repo, tc.build)
			assertSameIDs(t, got, tc.want)
		})
	}
}

// Token filters are backed by the token bloom indexes. A LIKE with a leading wildcard
// would read every granule instead, so this pins the behaviour the index exists for.
func TestTokenFiltersMatchWordsInText(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-tokens")
	seedSearchCorpus(ctx, t, f, tenant.ID)

	repo := chdata.NewSearchRepo(f.ClickHouse)

	got := searchFor(ctx, t, repo, func(b *query.Builder) {
		b.Where("user_agent", query.OpHasToken, "curl")
	})
	assertSameIDs(t, got, []string{"cf-blocked"})
}

func TestSearchIsTenantScoped(t *testing.T) {
	f := support.Shared(t)
	ctxA, tenantA := f.NewTenant(t, "search-tenant-a")
	ctxB, _ := f.NewTenant(t, "search-tenant-b")
	seedSearchCorpus(ctxA, t, f, tenantA.ID)

	repo := chdata.NewSearchRepo(f.ClickHouse)

	own := searchFor(ctxA, t, repo, func(*query.Builder) {})
	if len(own) != 3 {
		t.Fatalf("the owning tenant sees %d of its own 3 events", len(own))
	}

	other := searchFor(ctxB, t, repo, func(*query.Builder) {})
	if len(other) != 0 {
		t.Errorf("tenant B sees %d of tenant A's events", len(other))
	}
}

// The time range is the primary bound. An event outside it must not appear regardless
// of how well it matches every other filter.
func TestSearchHonoursTheTimeRange(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-range")
	seedSearchCorpus(ctx, t, f, tenant.ID)

	repo := chdata.NewSearchRepo(f.ClickHouse)
	page, err := repo.SearchEvents(ctx, chdata.EventQuery{
		Range: query.TimeRange{
			From: searchBase.Add(-48 * time.Hour), To: searchBase.Add(-24 * time.Hour),
		},
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if len(page.Items) != 0 {
		t.Errorf("got %d events from a range containing none", len(page.Items))
	}
}

// Paging must be total and stable against real storage, not only in the unit test's
// simulation of the ordering rule.
func TestPagingWalksEveryRowExactlyOnce(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-paging")

	const total = 25
	events := make([]chdata.NormalizedEvent, total)
	for i := range events {
		events[i] = chdata.NormalizedEvent{
			TenantID: tenant.ID, EventID: fmt.Sprintf("page-%02d", i),
			EventTime:  searchBase.Add(time.Duration(i) * time.Second),
			ReceivedAt: searchBase,
			Vendor:     vendors.Cloudflare, ClientIP: net.ParseIP("203.0.113.10"),
			RequestHost: "shop.example.com", RequestPath: "/checkout",
			RequestMethod: "GET", Verdict: vendors.VerdictAllowed, IngestVersion: 1,
		}
	}
	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f.Sync(t, "normalized_events")

	repo := chdata.NewSearchRepo(f.ClickHouse)
	seen := map[string]int{}
	var cursor query.Cursor

	for range 10 {
		page, err := repo.SearchEvents(ctx, chdata.EventQuery{
			Range: searchRange(), Cursor: cursor, PageSize: 7,
		})
		if err != nil {
			t.Fatalf("SearchEvents: %v", err)
		}
		for _, item := range page.Items {
			seen[item.EventID]++
		}
		if !page.HasMore() {
			break
		}
		cursor, err = query.DecodeCursor(page.NextCursor)
		if err != nil {
			t.Fatalf("DecodeCursor: %v", err)
		}
	}

	if len(seen) != total {
		t.Errorf("saw %d distinct rows, want %d — paging skipped some", len(seen), total)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("row %s returned %d times, want once", id, count)
		}
	}
}

// Events sharing a timestamp to the millisecond are routine: one vendor delivers a
// batch and every event lands in the same instant.
func TestPagingIsStableWhenTimestampsCollide(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-collisions")

	const total = 12
	events := make([]chdata.NormalizedEvent, total)
	for i := range events {
		events[i] = chdata.NormalizedEvent{
			TenantID: tenant.ID, EventID: fmt.Sprintf("batch-%02d", i),
			EventTime: searchBase, ReceivedAt: searchBase,
			Vendor: vendors.F5, ClientIP: net.ParseIP("203.0.113.10"),
			RequestHost: "shop.example.com", RequestPath: "/checkout",
			RequestMethod: "GET", Verdict: vendors.VerdictAllowed, IngestVersion: 1,
		}
	}
	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f.Sync(t, "normalized_events")

	repo := chdata.NewSearchRepo(f.ClickHouse)
	seen := map[string]int{}
	var cursor query.Cursor

	for range 8 {
		page, err := repo.SearchEvents(ctx, chdata.EventQuery{
			Range: searchRange(), Cursor: cursor, PageSize: 5,
		})
		if err != nil {
			t.Fatalf("SearchEvents: %v", err)
		}
		for _, item := range page.Items {
			seen[item.EventID]++
		}
		if !page.HasMore() {
			break
		}
		cursor, err = query.DecodeCursor(page.NextCursor)
		if err != nil {
			t.Fatalf("DecodeCursor: %v", err)
		}
	}

	if len(seen) != total {
		t.Errorf("saw %d of %d rows sharing one timestamp", len(seen), total)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("row %s returned %d times, want once", id, count)
		}
	}
}

// A single complete page reports an exact count; only a partial one is an estimate.
func TestTotalIsExactWhenTheResultFitsOnePage(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-totals")
	seedSearchCorpus(ctx, t, f, tenant.ID)

	repo := chdata.NewSearchRepo(f.ClickHouse)

	full, err := repo.SearchEvents(ctx, chdata.EventQuery{Range: searchRange(), PageSize: 100})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if full.TotalIsEstimate {
		t.Error("a complete single page was reported as an estimate")
	}
	if full.Total != 3 {
		t.Errorf("total = %d, want 3", full.Total)
	}

	partial, err := repo.SearchEvents(ctx, chdata.EventQuery{Range: searchRange(), PageSize: 2})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if !partial.TotalIsEstimate {
		t.Error("a partial page reported an exact total it cannot know")
	}
	if !partial.HasMore() {
		t.Error("a partial page did not offer a next cursor")
	}
}

// Re-ingestion must not duplicate a row in search results. FINAL is what guarantees
// that; without it an analyst counting occurrences counts merges instead of requests.
func TestRedeliveredEventAppearsOnce(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-redelivery")

	event := chdata.NormalizedEvent{
		TenantID: tenant.ID, EventID: "retry-1", EventTime: searchBase,
		ReceivedAt: searchBase, Vendor: vendors.Cloudflare,
		ClientIP: net.ParseIP("203.0.113.10"), RequestHost: "shop.example.com",
		RequestPath: "/checkout", RequestMethod: "GET",
		Verdict: vendors.VerdictAllowed, IngestVersion: 1,
	}

	repo := chdata.NewEventRepo(f.ClickHouse)
	if err := repo.InsertNormalized(ctx, []chdata.NormalizedEvent{event}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	event.IngestVersion = 2
	event.Verdict = vendors.VerdictBlocked
	if err := repo.InsertNormalized(ctx, []chdata.NormalizedEvent{event}); err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	f.Sync(t, "normalized_events")

	page, err := chdata.NewSearchRepo(f.ClickHouse).SearchEvents(ctx, chdata.EventQuery{
		Range: searchRange(), PageSize: 100,
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("got %d rows for one re-ingested event, want 1", len(page.Items))
	}
	if page.Items[0].Verdict != vendors.VerdictBlocked {
		t.Errorf("verdict = %q, want the latest version's value", page.Items[0].Verdict)
	}
}

func assertSameIDs(t *testing.T, got, want []string) {
	t.Helper()

	gotSet := map[string]bool{}
	for _, id := range got {
		gotSet[id] = true
	}
	wantSet := map[string]bool{}
	for _, id := range want {
		wantSet[id] = true
	}

	for id := range wantSet {
		if !gotSet[id] {
			t.Errorf("expected %s in the results, got %v", id, got)
		}
	}
	for id := range gotSet {
		if !wantSet[id] {
			t.Errorf("unexpected %s in the results, want %v", id, want)
		}
	}
}
