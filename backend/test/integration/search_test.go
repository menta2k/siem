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
			JA4: "t13d1516h2_8daaf6152771_b0da82dd1658",
			// A real detection: the WAF scores it 2 of 99, and 2 is the ATTACK end.
			WAFAttackScore: 2, WAFSQLiScore: 4, WAFXSSScore: 98, WAFRCEScore: 98,
			WAFAction: "log", WAFSource: "firewallManaged",
			RuleID: "waf-sqli", Score: score(0.9), ScoreKind: vendors.ScoreKindBot,
		},
		{
			EventID: "f5-allowed", Vendor: vendors.F5,
			ClientIP: net.ParseIP("198.51.100.7"), ClientCountry: "FR", ClientASN: 64513,
			RequestHost: "api.example.com", RequestPath: "/v1/orders",
			RequestMethod: "GET", HTTPStatus: 200,
			UserAgent: "Mozilla/5.0", Verdict: vendors.VerdictAllowed,
			// The SAME fingerprint as cf-blocked, on a different address and behind a
			// different user agent. That is the whole point of searching by it.
			JA4:    "t13d1516h2_8daaf6152771_b0da82dd1658",
			RuleID: "", Score: score(0.1), ScoreKind: vendors.ScoreKindBot,
		},
		{
			EventID: "dd-challenged", Vendor: vendors.DataDome,
			ClientIP: net.ParseIP("203.0.113.10"), ClientCountry: "DE", ClientASN: 64512,
			RequestHost: "shop.example.com", RequestPath: "/login",
			RequestMethod: "POST", HTTPStatus: 401,
			UserAgent: "python-requests/2.31", Verdict: vendors.VerdictChallenged,
			// A different stack, so an over-broad fingerprint filter shows up as this
			// row being swept in with the others.
			JA4: "t13d1517h2_abcdef123456_0123456789ab",
			// The SAME rule as cf-blocked, on a different host, but the WAF scores it 86
			// — the CLEAN end. This is the false-positive shape the tuning view exists
			// to separate from the row above, and a corpus where both scored alike would
			// pass without the feature working.
			WAFAttackScore: 86, WAFAction: "log", WAFSource: "firewallManaged",
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
		// The fingerprint identifies the client STACK, so it finds both rows that share
		// one even though they agree on no other identifier — different address,
		// different user agent, different vendor.
		"by ja4": {
			build: func(b *query.Builder) {
				b.Where("ja4", query.OpEqual, "t13d1516h2_8daaf6152771_b0da82dd1658")
			},
			want: []string{"cf-blocked", "f5-allowed"},
		},
		// The filter tuning is built on, and the one place the INVERTED scale bites:
		// "at most 20" means "scored as an attack", and it must not sweep in the
		// unscored rows, whose 0 would otherwise rank as the strongest signal of all.
		"by waf attack score, the attack end": {
			build: func(b *query.Builder) {
				b.Where("waf_attack_score", query.OpLessEqual, uint32(20))
				b.Where("waf_attack_score", query.OpGreaterEqual, uint32(1))
			},
			want: []string{"cf-blocked"},
		},
		"by waf action": {
			build: func(b *query.Builder) {
				b.Where("waf_action", query.OpEqual, "log")
			},
			want: []string{"cf-blocked", "dd-challenged"},
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

// Correlated records carry event ids, not fingerprints — the vendors that joined into
// one need not all have reported a JA4 — so searching correlations by fingerprint is a
// two-step lookup through the events. This is the first step, and it is the one that
// decides whether the correlated filter finds anything at all.
func TestEventIDsForResolvesAFingerprint(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-ja4-resolve")
	seedSearchCorpus(ctx, t, f, tenant.ID)

	repo := chdata.NewSearchRepo(f.ClickHouse)

	ids, err := repo.EventIDsFor(
		ctx, "ja4", "t13d1516h2_8daaf6152771_b0da82dd1658", searchRange())
	if err != nil {
		t.Fatalf("EventIDsFor: %v", err)
	}

	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	for _, want := range []string{"cf-blocked", "f5-allowed"} {
		if !got[want] {
			t.Errorf("EventIDsFor(ja4) = %v, want it to include %q", ids, want)
		}
	}
	if got["dd-challenged"] {
		t.Error("a different fingerprint was resolved as a match")
	}
}

// Resolving to nothing is a real answer — no event carried that fingerprint — and the
// caller has to render it as an empty result rather than drop the filter and return
// every correlation in the range.
func TestEventIDsForReportsAnUnmatchedFingerprint(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-ja4-miss")
	seedSearchCorpus(ctx, t, f, tenant.ID)

	ids, err := chdata.NewSearchRepo(f.ClickHouse).EventIDsFor(
		ctx, "ja4", "t13d0000h0_000000000000_000000000000", searchRange())
	if err != nil {
		t.Fatalf("EventIDsFor: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("EventIDsFor(unknown fingerprint) = %v, want none", ids)
	}
}

// THE COLUMNS MUST SURVIVE THE ROUND TRIP. normalizedColumns, the batch Append and
// scanNormalized are three lists that have to stay aligned; migration 0006 shifted them
// once in production and crash-looped the normalizer. Writing a row with distinct values
// in every WAF column and reading it back is what catches an off-by-one between them —
// values that differ from each other, so a shifted column cannot coincidentally match.
func TestWAFColumnsRoundTripThroughStorage(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-waf-roundtrip")

	want := chdata.NormalizedEvent{
		TenantID: tenant.ID, EventID: "waf-roundtrip", Vendor: vendors.Cloudflare,
		EventTime: searchBase, ReceivedAt: searchBase, IngestVersion: 1,
		RequestHost: "www.example.com", RequestPath: "/", RequestMethod: "GET",
		Verdict: vendors.VerdictMonitored,
		// Deliberately all different, so a shifted column shows up as a mismatch.
		WAFAttackScore: 2, WAFSQLiScore: 4, WAFXSSScore: 97, WAFRCEScore: 98,
		WAFAction: "log", WAFSource: "firewallManaged",
	}

	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(
		ctx, []chdata.NormalizedEvent{want},
	); err != nil {
		t.Fatalf("InsertNormalized: %v", err)
	}
	f.Sync(t, "normalized_events")

	got, err := chdata.NewEventRepo(f.ClickHouse).GetNormalized(ctx, "waf-roundtrip")
	if err != nil {
		t.Fatalf("GetNormalized: %v", err)
	}

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"WAFAttackScore", got.WAFAttackScore, want.WAFAttackScore},
		{"WAFSQLiScore", got.WAFSQLiScore, want.WAFSQLiScore},
		{"WAFXSSScore", got.WAFXSSScore, want.WAFXSSScore},
		{"WAFRCEScore", got.WAFRCEScore, want.WAFRCEScore},
		{"WAFAction", got.WAFAction, want.WAFAction},
		{"WAFSource", got.WAFSource, want.WAFSource},
		// Carried alongside, because a shift in the WAF block would land here.
		{"Verdict", got.Verdict, want.Verdict},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

// Redelivery plus paging, which the single-event case above cannot cover.
//
// SearchEvents drops FINAL and collapses versions with LIMIT 1 BY instead, because FINAL
// merges every part in the time range before the WHERE clause runs and so defeats the
// skip indexes — filtering a day of events by rule took 11.1s with it and 0.054s
// without. The substitution is only sound while a row's SORT column cannot move between
// versions: if it could, the versions would sort onto different pages, and the cursor
// that excludes the newest would still admit the superseded one. That is why
// SearchCorrelated keeps FINAL, and this test is what pins the difference.
//
// So: a re-ingested event sitting mid-page, walked one row at a time.
func TestRedeliveredEventAppearsOnceWhenPaging(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "search-redelivery-paging")

	repo := chdata.NewEventRepo(f.ClickHouse)
	newEvent := func(id string, offset time.Duration, version uint64, verdict string,
	) chdata.NormalizedEvent {
		return chdata.NormalizedEvent{
			TenantID: tenant.ID, EventID: id, EventTime: searchBase.Add(offset),
			ReceivedAt: searchBase.Add(offset), Vendor: vendors.Cloudflare,
			ClientIP: net.ParseIP("203.0.113.11"), RequestHost: "paging.example.com",
			RequestPath: "/checkout", RequestMethod: "GET",
			Verdict: verdict, IngestVersion: version,
		}
	}

	events := []chdata.NormalizedEvent{
		newEvent("page-1", 3*time.Second, 1, vendors.VerdictAllowed),
		newEvent("page-2", 2*time.Second, 1, vendors.VerdictAllowed),
		newEvent("page-3", 1*time.Second, 1, vendors.VerdictAllowed),
	}
	if err := repo.InsertNormalized(ctx, events); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// The middle row arrives again, corrected. Its event_time is unchanged — that is the
	// property the whole substitution rests on.
	amended := newEvent("page-2", 2*time.Second, 2, vendors.VerdictBlocked)
	if err := repo.InsertNormalized(ctx, []chdata.NormalizedEvent{amended}); err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	f.Sync(t, "normalized_events")

	search := chdata.NewSearchRepo(f.ClickHouse)
	var seen []string
	verdicts := map[string]string{}
	var cursor query.Cursor

	// One row per page, so every page boundary falls somewhere different — including
	// straight after the re-ingested row, which is the position that would resurrect it.
	for range 5 {
		page, err := search.SearchEvents(ctx, chdata.EventQuery{
			Range: searchRange(), PageSize: 1, Cursor: cursor,
		})
		if err != nil {
			t.Fatalf("SearchEvents: %v", err)
		}
		if len(page.Items) == 0 {
			break
		}
		for _, item := range page.Items {
			seen = append(seen, item.EventID)
			verdicts[item.EventID] = item.Verdict
		}
		if !page.HasMore() {
			break
		}
		cursor = query.Cursor{
			EventTime: page.Items[len(page.Items)-1].EventTime,
			ID:        page.Items[len(page.Items)-1].EventID,
		}
	}

	assertSameIDs(t, seen, []string{"page-1", "page-2", "page-3"})
	if len(seen) != 3 {
		t.Fatalf("walked %d rows for 3 events, want 3: %v — a superseded version came "+
			"back on a later page", len(seen), seen)
	}
	if verdicts["page-2"] != vendors.VerdictBlocked {
		t.Errorf("page-2 verdict = %q, want the latest version's value",
			verdicts["page-2"])
	}
}
