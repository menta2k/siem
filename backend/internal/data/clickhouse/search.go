package clickhouse

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
)

// SearchRepo runs analyst searches over events and correlated requests.
//
// Every method takes an already-VALIDATED filter set. This type deliberately cannot
// build a predicate from a raw field name: the allowlist lives in internal/query and
// the only thing that arrives here is a rendered clause with its bound arguments.
type SearchRepo struct {
	client *Client
}

// NewSearchRepo builds the repository.
func NewSearchRepo(client *Client) *SearchRepo {
	return &SearchRepo{client: client}
}

// Page is one page of results with the cursor for the next.
type Page[T any] struct {
	Items      []T
	NextCursor string
	// TotalIsEstimate reports that Total is NOT the full match count.
	//
	// An exact count over hundreds of millions of rows cannot meet the latency budget,
	// so the API says when a number is approximate instead of implying a precision it
	// does not have. When a result fits in a single page there is nothing to estimate:
	// Total is then the real count and this is false.
	TotalIsEstimate bool
	// Total is the number of matches when TotalIsEstimate is false, and the number
	// seen so far when it is true. Signed to match the API type: the value is bounded
	// by the page size, so an unsigned counter buys nothing and costs a conversion at
	// every boundary.
	Total int64
}

// HasMore reports whether another page exists.
func (p Page[T]) HasMore() bool { return p.NextCursor != "" }

// paginate trims the lookahead row and fills in the paging fields.
//
// The lookahead is why no COUNT query is needed: asking for one row more than the page
// answers "is there another page" exactly, for the cost of a single row.
func paginate[T any](items []T, pageSize int32, cursorOf func(T) query.Cursor) Page[T] {
	page := Page[T]{}

	// Compared in int rather than narrowing len() to int32: the page size is small and
	// already bounded, so widening is both safe and free of a conversion to justify.
	if len(items) > int(pageSize) {
		items = items[:pageSize]
		page.NextCursor = query.EncodeCursor(cursorOf(items[len(items)-1]))
		// More rows exist beyond this page, so the count is a floor, not a total.
		page.TotalIsEstimate = true
	}

	page.Items = items
	page.Total = int64(len(items))
	return page
}

const eventSearchColumns = `event_id, event_time, vendor, feed_id, vendor_request_id,
	vendor_event_id,
	client_ip, client_ip_shared, client_asn, client_country, request_host, request_path,
	request_query, request_method, user_agent, http_status, ja4,
	waf_attack_score, waf_sqli_score, waf_xss_score, waf_rce_score, waf_action, waf_source,
	verdict, verdict_reason,
	rule_id, rule_ids, score, score_kind`

// EventSearchResult is one row of an event search.
//
// A narrower projection than NormalizedEvent: the raw payload and the vendor-native
// extras are deliberately excluded. A results page holding a thousand raw payloads
// would be tens of megabytes, and the analyst has not asked for them yet — the detail
// endpoint fetches them for the one row they open.
type EventSearchResult struct {
	EventID   string
	EventTime time.Time
	Vendor    string
	FeedID    uuid.UUID

	VendorRequestID string
	// VendorEventID is F5's support_id: the vendor's own reference for its record.
	VendorEventID  string
	ClientIP       net.IP
	ClientIPShared bool
	ClientASN      uint32
	ClientCountry  string

	RequestHost   string
	RequestPath   string
	RequestQuery  string
	RequestMethod string
	UserAgent     string
	HTTPStatus    uint16
	JA4           string

	// The vendor's WAF scoring, on Cloudflare's inverted 1-99 scale where 1 is an
	// attack. 0 means not scored. See migration 0015.
	WAFAttackScore uint8
	WAFSQLiScore   uint8
	WAFXSSScore    uint8
	WAFRCEScore    uint8
	WAFAction      string
	WAFSource      string

	Verdict       string
	VerdictReason string
	RuleID        string
	RuleIDs       []string
	Score         *float32
	ScoreKind     string
}

// EventQuery is a validated event search.
type EventQuery struct {
	Range      query.TimeRange
	Conditions string
	Args       []any
	Cursor     query.Cursor
	PageSize   int32
}

// SearchEvents returns one page of normalized events.
//
// Re-ingested events are collapsed with LIMIT 1 BY rather than FINAL — see
// query.Table.Dedupe for why the obvious spelling is the slow one.
func (r *SearchRepo) SearchEvents(
	ctx context.Context, q EventQuery,
) (Page[EventSearchResult], error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Page[EventSearchResult]{}, err
	}

	sql := "SELECT " + eventSearchColumns + " FROM normalized_events " +
		"WHERE tenant_id = ? AND event_time >= ? AND event_time < ?"
	args := []any{tenantID, q.Range.From, q.Range.To}

	sql += q.Conditions
	args = append(args, q.Args...)

	cursorSQL, cursorArgs := query.EventsTable.CursorCondition(q.Cursor)
	sql += cursorSQL
	args = append(args, cursorArgs...)

	// One row beyond the page, so "is there a next page" is answered without a second
	// query and without a count. The extra row is trimmed before returning.
	sql += query.EventsTable.OrderBy() + query.EventsTable.Dedupe() + " LIMIT ?"
	args = append(args, q.PageSize+1)

	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return Page[EventSearchResult]{}, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]EventSearchResult, 0, q.PageSize)
	for rows.Next() {
		item, err := scanEventSearchResult(rows)
		if err != nil {
			return Page[EventSearchResult]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[EventSearchResult]{}, query.TranslateError(err)
	}

	return paginate(items, q.PageSize, func(e EventSearchResult) query.Cursor {
		return query.Cursor{EventTime: e.EventTime, ID: e.EventID}
	}), nil
}

func scanEventSearchResult(row rowScanner) (EventSearchResult, error) {
	var (
		result   EventSearchResult
		clientIP net.IP
	)
	if err := row.Scan(
		&result.EventID, &result.EventTime, &result.Vendor, &result.FeedID,
		&result.VendorRequestID, &result.VendorEventID,
		&clientIP, &result.ClientIPShared, &result.ClientASN,
		&result.ClientCountry, &result.RequestHost, &result.RequestPath,
		&result.RequestQuery, &result.RequestMethod, &result.UserAgent,
		&result.HTTPStatus, &result.JA4,
		&result.WAFAttackScore, &result.WAFSQLiScore, &result.WAFXSSScore,
		&result.WAFRCEScore, &result.WAFAction, &result.WAFSource,
		&result.Verdict, &result.VerdictReason, &result.RuleID,
		&result.RuleIDs, &result.Score, &result.ScoreKind,
	); err != nil {
		return EventSearchResult{}, fmt.Errorf("scan event search result: %w", err)
	}
	result.ClientIP = ipOrNil(clientIP)
	return result, nil
}

// CorrelatedQuery is a validated correlated-request search.
type CorrelatedQuery struct {
	Range      query.TimeRange
	Conditions string
	Args       []any
	Cursor     query.Cursor
	PageSize   int32
}

// SearchCorrelated returns one page of correlated requests.
//
// This one KEEPS FINAL, unlike SearchEvents. The cheap substitute there is unsafe here:
// last_event_time is both the cursor's sort column and a value that ADVANCES when a late
// vendor amends a record, so the versions of one record sort to different pages. Page 1
// keeps the newest, then page 2's cursor excludes that version while still admitting the
// superseded one — and the record appears twice, the second time reporting fewer vendors
// than actually joined. Production holds a record in exactly that state, so this is
// observed rather than hypothetical. An event's time never moves, which is what makes
// the substitution safe for SearchEvents and only there.
//
// It also costs far less here: 1.6s over 24h against 11.1s, because this table holds
// ~10M rows to normalized_events' ~38M and is not the query anyone reported as slow.
func (r *SearchRepo) SearchCorrelated(
	ctx context.Context, q CorrelatedQuery,
) (Page[CorrelatedRequest], error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Page[CorrelatedRequest]{}, err
	}

	sql := "SELECT " + correlatedColumns + " FROM correlated_requests FINAL " +
		"WHERE tenant_id = ? AND window_start >= ? AND window_start < ?"
	args := []any{tenantID, q.Range.From, q.Range.To}

	sql += q.Conditions
	args = append(args, q.Args...)

	cursorSQL, cursorArgs := query.CorrelatedTable.CursorCondition(q.Cursor)
	sql += cursorSQL
	args = append(args, cursorArgs...)

	sql += query.CorrelatedTable.OrderBy() + " LIMIT ?"
	args = append(args, q.PageSize+1)

	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return Page[CorrelatedRequest]{}, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]CorrelatedRequest, 0, q.PageSize)
	for rows.Next() {
		item, err := scanCorrelated(rows)
		if err != nil {
			return Page[CorrelatedRequest]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[CorrelatedRequest]{}, query.TranslateError(err)
	}

	return paginate(items, q.PageSize, func(c CorrelatedRequest) query.Cursor {
		return query.Cursor{EventTime: c.LastEventTime, ID: c.CorrelationID.String()}
	}), nil
}

// MaxIdentifierEvents bounds how many events one identifier may resolve to.
//
// A CF-Ray reaches at most one row per vendor per hop — five or six in this topology —
// and an F5 support_id exactly one. The bound is generous against that so a legitimate
// lookup is never truncated, while still refusing to build an unbounded IN list from a
// value an analyst pasted in.
const MaxIdentifierEvents = 100

// rowCursor is the iteration surface of a result set, so the scanning below can be
// exercised without a database.
type rowCursor interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// IdentifiedEvents is what one identifier resolved to.
//
// The SPAN is the half that makes the lookup affordable. Correlated records are searched
// by hasAny(event_ids, ...), which no index answers, so the range decides the cost: over a
// week it reads 69 million rows and takes 25 seconds, and over the half hour the events
// actually happened in it reads half a million. The events know when they were, so the
// caller never has to guess.
type IdentifiedEvents struct {
	IDs   []string
	First time.Time
	Last  time.Time
}

// EventIDsFor resolves a vendor identifier to the events carrying it.
//
// Correlated records store event ids, not identifiers, so searching them by ray or
// support id is a two-step lookup rather than a column comparison. Both columns carry
// bloom-filter indexes, so this step is an indexed point lookup and not a scan.
//
// Resolving to NOTHING is a real answer — the identifier matched no event — and the
// caller has to render it as an empty result rather than as an absent filter.
func (r *SearchRepo) EventIDsFor(
	ctx context.Context, column, value string, rng query.TimeRange,
) (IdentifiedEvents, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return IdentifiedEvents{}, err
	}

	// The column is chosen from a fixed set by the caller, never taken from input.
	switch column {
	case "vendor_request_id", "vendor_event_id", "linked_request_id", "ja4":
	default:
		return IdentifiedEvents{}, fmt.Errorf(
			"event lookup: unsupported identifier column %q", column)
	}

	sql := fmt.Sprintf(
		`SELECT event_id, event_time FROM normalized_events
		 WHERE tenant_id = ? AND event_time >= ? AND event_time < ? AND %s = ?
		 LIMIT %d`, column, MaxIdentifierEvents)

	rows, err := r.client.Query(ctx, sql, tenantID, rng.From, rng.To, value)
	if err != nil {
		return IdentifiedEvents{}, fmt.Errorf("resolve identifier: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanIdentifiedEvents(rows)
}

// scanIdentifiedEvents collects the resolved events and the span they cover.
//
// Deduplicated here rather than with DISTINCT, because the timestamps have to be read to
// know the span and a DISTINCT over two columns would no longer dedupe the id.
func scanIdentifiedEvents(rows rowCursor) (IdentifiedEvents, error) {
	var (
		out  = IdentifiedEvents{IDs: make([]string, 0, 8)}
		seen = make(map[string]struct{}, 8)
	)
	for rows.Next() {
		var (
			eventID   string
			eventTime time.Time
		)
		if err := rows.Scan(&eventID, &eventTime); err != nil {
			return IdentifiedEvents{}, fmt.Errorf("scan event id: %w", err)
		}
		if _, duplicate := seen[eventID]; duplicate {
			continue
		}
		seen[eventID] = struct{}{}
		out.IDs = append(out.IDs, eventID)

		if out.First.IsZero() || eventTime.Before(out.First) {
			out.First = eventTime
		}
		if eventTime.After(out.Last) {
			out.Last = eventTime
		}
	}
	return out, rows.Err()
}
