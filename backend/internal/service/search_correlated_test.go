package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
)

// Looking a request up by an identifier, which is how the console gets from an event to
// the whole request. The identifier is the answer; the range the page happened to be
// showing has nothing to do with it.

var (
	searchNow   = time.Date(2026, 8, 18, 6, 0, 0, 0, time.UTC)
	eventMoment = time.Date(2026, 8, 17, 13, 35, 12, 0, time.UTC)
)

// stubSearcher records the correlated query it was handed.
type stubSearcher struct {
	resolved chdata.IdentifiedEvents

	gotIdentifierRange query.TimeRange
	gotCorrelated      chdata.CorrelatedQuery
}

func (s *stubSearcher) SearchEvents(
	context.Context, chdata.EventQuery,
) (EventPage, error) {
	return EventPage{}, nil
}

func (s *stubSearcher) SearchCorrelated(
	_ context.Context, q chdata.CorrelatedQuery,
) (CorrelatedPage, error) {
	s.gotCorrelated = q
	return CorrelatedPage{}, nil
}

func (s *stubSearcher) EventIDsFor(
	_ context.Context, _, _ string, rng query.TimeRange,
) (chdata.IdentifiedEvents, error) {
	s.gotIdentifierRange = rng
	return s.resolved, nil
}

func searchService(searcher EventSearcher) *SearchService {
	s := NewSearchService(searcher, nil, nil, query.DefaultLimits(), nil, nil, nil, nil)
	s.now = func() time.Time { return searchNow }
	return s
}

func searchContext() context.Context {
	return tenancy.WithTenant(context.Background(), tenancy.Tenant{
		ID: uuid.MustParse("979cc324-0ba6-43b3-b9ad-c30412792839"),
	})
}

func rayRequest(hours int) *pb.SearchCorrelatedRequest {
	return &pb.SearchCorrelatedRequest{
		TimeRange: &pb.TimeRange{
			From: timestamppb.New(searchNow.Add(-time.Duration(hours) * time.Hour)),
			To:   timestamppb.New(searchNow),
		},
		Filters: &pb.CorrelatedFilters{VendorRequestId: "a2c90f883c2de5b6"},
	}
}

// THE ONE THAT MAKES THE LOOKUP AFFORDABLE. Correlated records are searched with
// hasAny(event_ids, ...), which no index answers, so the range decides the cost: measured
// on production a week reads 69 million rows and takes 25 seconds, while the half hour the
// events actually happened in reads half a million. The events know when they were.
func TestAnIdentifierLookupIsNarrowedToWhenTheEventsHappened(t *testing.T) {
	searcher := &stubSearcher{resolved: chdata.IdentifiedEvents{
		IDs:   []string{"event-1", "event-2"},
		First: eventMoment,
		Last:  eventMoment.Add(2 * time.Second),
	}}

	if _, err := searchService(searcher).SearchCorrelated(
		searchContext(), rayRequest(24)); err != nil {
		t.Fatalf("SearchCorrelated: %v", err)
	}

	got := searcher.gotCorrelated.Range
	if span := got.To.Sub(got.From); span > time.Hour {
		t.Errorf("the correlated scan spans %s; the events span two seconds", span)
	}
	if !got.From.Before(eventMoment) || !got.To.After(eventMoment) {
		t.Errorf("range %s..%s does not contain the event at %s",
			got.From, got.To, eventMoment)
	}
}

// The identifier is resolved inside the range the caller asked for, and not beyond it.
//
// It is tempting to search further, because an event older than the window on screen
// reports as having no correlation — which is exactly the confusion that started this. But
// a server that quietly reads outside the requested range makes every range filter a lie.
// The window a lookup needs is the CALLER's to choose, and the console now chooses one
// wide enough when it links to a specific request.
func TestAnIdentifierIsResolvedWithinTheRequestedRange(t *testing.T) {
	searcher := &stubSearcher{resolved: chdata.IdentifiedEvents{
		IDs: []string{"event-1"}, First: eventMoment, Last: eventMoment,
	}}

	if _, err := searchService(searcher).SearchCorrelated(
		searchContext(), rayRequest(1)); err != nil {
		t.Fatalf("SearchCorrelated: %v", err)
	}

	if searcher.gotIdentifierRange.From.Before(searchNow.Add(-time.Hour)) {
		t.Errorf("the identifier was looked for from %s, outside the hour the caller asked "+
			"about", searcher.gotIdentifierRange.From)
	}
}

// The caller's range is a PERMISSION, not a hint. Narrowing to the events is an
// optimization; returning a record from outside the range the analyst asked about would be
// answering a different question.
func TestNarrowingNeverWidensTheCallersRange(t *testing.T) {
	rng := query.TimeRange{From: searchNow.Add(-time.Hour), To: searchNow}
	resolved := chdata.IdentifiedEvents{
		First: searchNow.Add(-48 * time.Hour),
		Last:  searchNow.Add(48 * time.Hour),
	}

	got := narrowToEvents(rng, resolved)

	if got.From.Before(rng.From) || got.To.After(rng.To) {
		t.Errorf("range %s..%s escaped the caller's %s..%s",
			got.From, got.To, rng.From, rng.To)
	}
}

// A record's window_start is the start of the bucket its events fell into, so it can sit
// slightly BEFORE the earliest event. Narrowing exactly to the events would step over the
// record the lookup exists to find.
func TestTheNarrowedRangeLeavesRoomForTheCorrelationWindow(t *testing.T) {
	rng := query.TimeRange{From: searchNow.Add(-72 * time.Hour), To: searchNow}
	resolved := chdata.IdentifiedEvents{First: eventMoment, Last: eventMoment}

	got := narrowToEvents(rng, resolved)

	if !got.From.Before(eventMoment) {
		t.Error("the window starts at or after the event, so a record bucketed just " +
			"before it would be missed")
	}
	if !got.To.After(eventMoment) {
		t.Error("the window ends at or before the event")
	}
}

// Nothing to narrow to is not a reason to invent a range: a resolver that reported no
// times must leave the caller's range alone.
func TestWithoutEventTimesTheRangeIsUntouched(t *testing.T) {
	rng := query.TimeRange{From: searchNow.Add(-time.Hour), To: searchNow}

	if got := narrowToEvents(rng, chdata.IdentifiedEvents{IDs: []string{"e1"}}); got != rng {
		t.Errorf("range = %+v, want it unchanged", got)
	}
}

// An identifier that matched no event is a real answer — "no such request" — and must not
// come back as an unfiltered page of everything in the range.
func TestAnIdentifierThatMatchesNothingReturnsNothing(t *testing.T) {
	searcher := &stubSearcher{}

	page, err := searchService(searcher).SearchCorrelated(searchContext(), rayRequest(24))
	if err != nil {
		t.Fatalf("SearchCorrelated: %v", err)
	}

	if len(page.GetItems()) != 0 {
		t.Error("an unmatched identifier returned records")
	}
	if searcher.gotCorrelated.Conditions != "" {
		t.Error("the correlated table was searched for an identifier that matched no event")
	}
}
