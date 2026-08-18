package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
)

// Linking one event to the record it joined into.
//
// An analyst opens an event and the next question is always the same: what did the OTHER
// vendors do with this request. The answer exists — the correlated record — and until now
// the detail view could not name it, because an event does not carry a correlation id.

// stubEventReader returns one event and its payload.
type stubEventReader struct {
	event chdata.NormalizedEvent
}

func (s stubEventReader) GetNormalized(
	_ context.Context, _ string,
) (chdata.NormalizedEvent, error) {
	return s.event, nil
}

func (s stubEventReader) GetRawPayload(
	_ context.Context, _ string, _ chdata.RawPayloadHint,
) (chdata.RawPayload, error) {
	return chdata.RawPayload{}, chdata.ErrNotFound
}

// stubLocator answers the correlation lookup, recording how it was asked.
type stubLocator struct {
	correlationID uuid.UUID
	err           error
	delay         time.Duration

	gotEventID string
	gotTime    time.Time
}

func (s *stubLocator) CorrelationForEvent(
	ctx context.Context, eventID string, eventTime time.Time,
) (uuid.UUID, error) {
	s.gotEventID, s.gotTime = eventID, eventTime
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		}
	}
	return s.correlationID, s.err
}

var correlatedEvent = chdata.NormalizedEvent{
	EventID:   "d1a19ac1024a7c411f93567f5aa2d6965fd6da36ee7568b2c547903cce640379",
	EventTime: time.Date(2026, 8, 17, 13, 35, 12, 0, time.UTC),
	Vendor:    "cloudflare",
}

func detailService(locator CorrelationLocator) *SearchService {
	service := NewSearchService(
		&stubSearcher{}, stubEventReader{event: correlatedEvent}, nil,
		query.DefaultLimits(), nil, nil, nil, nil)
	if locator != nil {
		service = service.WithCorrelations(locator)
	}
	return service
}

func detailOf(t *testing.T, service *SearchService) *pb.EventDetail {
	t.Helper()
	detail, err := service.GetEvent(searchContext(), &pb.GetEventRequest{
		EventId: correlatedEvent.EventID,
	})
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	return detail
}

// THE LINK ITSELF. Without it an analyst reading one vendor's verdict has no way from here
// to what the other vendors did with the same request, which is the question the event was
// opened to answer.
func TestAnEventNamesTheRecordItWasCorrelatedInto(t *testing.T) {
	want := uuid.MustParse("78ce7e59-1af7-49f2-a5a4-77caff740f01")
	detail := detailOf(t, detailService(&stubLocator{correlationID: want}))

	if detail.GetCorrelationId() != want.String() {
		t.Errorf("correlation id = %q, want %q", detail.GetCorrelationId(), want)
	}
}

// THE TIME IS WHAT MAKES IT AFFORDABLE. Correlated records are searched by event id, which
// no column is ordered on; bounded to the minutes around the event that reads half a
// million rows, and unbounded it reads the whole 90-day retention and is cancelled.
func TestTheLookupIsGivenTheEventsOwnTime(t *testing.T) {
	locator := &stubLocator{correlationID: uuid.New()}
	detailOf(t, detailService(locator))

	if locator.gotEventID != correlatedEvent.EventID {
		t.Errorf("looked up %q", locator.gotEventID)
	}
	if !locator.gotTime.Equal(correlatedEvent.EventTime) {
		t.Errorf("looked up at %s, want the event's own time %s",
			locator.gotTime, correlatedEvent.EventTime)
	}
}

// An event no other vendor saw is correlated with nothing. That is a fact about the
// traffic, not a failure, and the rest of the detail view must still render.
func TestAnUncorrelatedEventStillRenders(t *testing.T) {
	detail := detailOf(t, detailService(&stubLocator{err: chdata.ErrNotFound}))

	if detail.GetCorrelationId() != "" {
		t.Errorf("correlation id = %q, want none", detail.GetCorrelationId())
	}
	if detail.GetSummary().GetEventId() != correlatedEvent.EventID {
		t.Error("the event itself did not survive an absent correlation")
	}
}

// THE DIALOG MUST NOT HANG ON IT. This is the last of three reads behind a view an analyst
// is waiting on, and a link that fails to resolve costs one click — the view still offers
// the lookup by ray — while a dialog that never opens costs the whole answer.
func TestASlowLookupDoesNotHoldUpTheEvent(t *testing.T) {
	service := detailService(&stubLocator{
		correlationID: uuid.New(), delay: 2 * time.Second,
	})
	service.correlationTimeout = 10 * time.Millisecond

	done := make(chan *pb.EventDetail, 1)
	go func() {
		detail, err := service.GetEvent(searchContext(), &pb.GetEventRequest{
			EventId: correlatedEvent.EventID,
		})
		if err != nil {
			done <- nil
			return
		}
		done <- detail
	}()

	select {
	case detail := <-done:
		if detail == nil {
			t.Fatal("a slow correlation lookup failed the whole event read")
		}
		if detail.GetCorrelationId() != "" {
			t.Error("a lookup that timed out still produced a link")
		}
	case <-time.After(time.Second):
		t.Fatal("the event read is still waiting on the correlation lookup")
	}
}

// A deployment without the locator keeps every other part of the view: absent is what an
// uncorrelated event renders anyway.
func TestWithoutALocatorTheDetailStillLoads(t *testing.T) {
	detail := detailOf(t, detailService(nil))

	if detail.GetCorrelationId() != "" || detail.GetSummary() == nil {
		t.Errorf("detail = %+v, want the event with no correlation link", detail)
	}
}

// A failing lookup is rendered as absent rather than as an error, for the same reason a
// slow one is — but it must not be mistaken for a correlated id either.
func TestAFailedLookupDoesNotInventALink(t *testing.T) {
	detail := detailOf(t, detailService(&stubLocator{err: errors.New("connection lost")}))

	if detail.GetCorrelationId() != "" {
		t.Errorf("correlation id = %q after a failed lookup", detail.GetCorrelationId())
	}
}
