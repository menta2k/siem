package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/service"
)

type stubCorrelationHealth struct {
	health chdata.CorrelationHealth
	err    error
}

func (s stubCorrelationHealth) GetCorrelationHealth(
	context.Context,
) (chdata.CorrelationHealth, error) {
	return s.health, s.err
}

func dashboardsWithCorrelation(reader service.CorrelationHealthReader) *service.DashboardsService {
	return service.NewDashboardsService(
		nil, nil, nil, query.Limits{}, nil, nil, nil, reader)
}

// The verdict is the server's. The console shows a word, and if it derived that word
// itself there would be two definitions of "losing data" to keep in step.
func TestCorrelationHealthIsJudgedOnTheServer(t *testing.T) {
	at := time.Date(2026, 8, 18, 12, 33, 0, 0, time.UTC)

	svc := dashboardsWithCorrelation(stubCorrelationHealth{
		health: chdata.CorrelationHealth{
			EventsFiled: 172_000, WindowsClosed: 900, WindowsDroppedEmpty: 1_701_942,
			RecordsEmitted: 900, ClaimLag: 90 * time.Minute,
			WindowTTL: 19 * time.Minute, LastRecordAt: at,
		},
	})

	got, err := svc.GetCorrelationHealth(context.Background(), &pb.DashboardRequest{})
	if err != nil {
		t.Fatalf("GetCorrelationHealth(): %v", err)
	}

	if got.GetStatus() != string(chdata.CorrelationLosing) {
		t.Errorf("status = %q, want %q", got.GetStatus(), chdata.CorrelationLosing)
	}
	if got.GetClaimLagMs() != uint64((90 * time.Minute).Milliseconds()) {
		t.Errorf("claim lag = %dms", got.GetClaimLagMs())
	}
	// Without the TTL the console cannot say whether the lag matters.
	if got.GetWindowTtlMs() != uint64((19 * time.Minute).Milliseconds()) {
		t.Errorf("window ttl = %dms", got.GetWindowTtlMs())
	}
	if !got.GetLastRecordAt().AsTime().Equal(at) {
		t.Errorf("last record at = %s, want %s", got.GetLastRecordAt().AsTime(), at)
	}
}

// A record that has never been emitted must leave the timestamp UNSET, not zero: the
// console renders an unset time as "never" and a zero one as 1970, and the second reads
// as a pipeline that stopped 56 years ago.
func TestCorrelationHealthLeavesAnUnknownLastRecordUnset(t *testing.T) {
	svc := dashboardsWithCorrelation(stubCorrelationHealth{
		health: chdata.CorrelationHealth{EventsFiled: 10},
	})

	got, err := svc.GetCorrelationHealth(context.Background(), &pb.DashboardRequest{})
	if err != nil {
		t.Fatalf("GetCorrelationHealth(): %v", err)
	}
	if got.GetLastRecordAt() != nil {
		t.Errorf("last record at = %v, want unset", got.GetLastRecordAt().AsTime())
	}
	if got.GetStatus() != string(chdata.CorrelationStalled) {
		t.Errorf("status = %q, want stalled: events were filed and nothing came out",
			got.GetStatus())
	}
}

// A deployment whose processor has not yet written the table must still load the page.
// The panel saying "nothing to report" is worth more than a dashboard that 500s.
func TestCorrelationHealthIsIdleWithoutAReader(t *testing.T) {
	got, err := dashboardsWithCorrelation(nil).
		GetCorrelationHealth(context.Background(), &pb.DashboardRequest{})
	if err != nil {
		t.Fatalf("GetCorrelationHealth(): %v", err)
	}
	if got.GetStatus() != string(chdata.CorrelationIdle) {
		t.Errorf("status = %q, want idle", got.GetStatus())
	}
}

// A failed read is an error, not a healthy panel. Reporting "healthy" because the
// health query itself failed is the exact inversion this feature exists to prevent.
func TestCorrelationHealthReportsAFailedRead(t *testing.T) {
	_, err := dashboardsWithCorrelation(stubCorrelationHealth{
		err: errors.New("clickhouse unavailable"),
	}).GetCorrelationHealth(context.Background(), &pb.DashboardRequest{})
	if err == nil {
		t.Fatal("a failed health read was reported as a healthy pipeline")
	}
}
