package correlate

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
)

// backlogStore is a schedule holding more closed windows than one tick may claim, with
// no member state behind any of them.
//
// That is production's failed state exactly: the closer fell behind, the members it
// eventually claimed had already passed their TTL, and every window closed empty. What
// matters here is only how fast the schedule is drained, so nothing else is modelled.
type backlogStore struct {
	mu       sync.Mutex
	schedule []string
	drained  chan struct{}
	once     sync.Once
}

func newBacklogStore(windows int) *backlogStore {
	schedule := make([]string, 0, windows)
	for i := range windows {
		schedule = append(schedule,
			uuid.Nil.String()+"\x00t2|window-"+strconv.Itoa(i))
	}
	return &backlogStore{schedule: schedule, drained: make(chan struct{})}
}

func (s *backlogStore) ZPopDue(
	_ context.Context, _ string, _ float64, limit int64,
) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	claimed := min(int(limit), len(s.schedule))
	popped := s.schedule[:claimed]
	s.schedule = s.schedule[claimed:]
	if len(s.schedule) == 0 {
		s.once.Do(func() { close(s.drained) })
	}
	return popped, nil
}

func (s *backlogStore) remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.schedule)
}

func (s *backlogStore) LRangeMany(
	_ context.Context, keys []string,
) (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (s *backlogStore) LookupMany(
	_ context.Context, _ []string,
) (map[string]string, error) {
	return map[string]string{}, nil
}

func (s *backlogStore) RPush(context.Context, string, string, time.Duration) (int64, error) {
	return 0, nil
}
func (s *backlogStore) RPushMany(context.Context, []window.ListEntry) error { return nil }
func (s *backlogStore) ZAddMany(context.Context, []window.ScoreEntry) error { return nil }
func (s *backlogStore) LRange(context.Context, string) ([]string, error)    { return nil, nil }
func (s *backlogStore) Get(context.Context, string) (string, error)         { return "", nil }
func (s *backlogStore) Lookup(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (s *backlogStore) SetNX(
	context.Context, string, string, time.Duration,
) (bool, error) {
	return true, nil
}
func (s *backlogStore) ZAdd(
	context.Context, string, string, float64, time.Duration,
) error {
	return nil
}

// nothingStored is a CorrelatedStore for a closer that has nothing to write.
type nothingStored struct{}

func (nothingStored) Insert(context.Context, []chdata.CorrelatedRequest) error { return nil }
func (nothingStored) Versions(
	context.Context, []uuid.UUID,
) (map[uuid.UUID]uint64, error) {
	return map[uuid.UUID]uint64{}, nil
}
func (nothingStored) ByIDs(
	context.Context, []uuid.UUID,
) (map[uuid.UUID]chdata.CorrelatedRequest, error) {
	return map[uuid.UUID]chdata.CorrelatedRequest{}, nil
}

// A backlog must drain at the speed of the work, not at one tick's claim per interval.
//
// Run used to sleep for the poll interval after every tick, including the ticks that
// stopped on the pass bound with the schedule still full. That capped the closer at
// MaxPassesPerTick*batch per interval — under a thousand windows a second — which is
// slower than production files them. Once behind, it never caught up: it kept claiming
// windows whose member state had expired and wrote nothing, for hours.
func TestRunDrainsABacklogWithoutWaitingForTheInterval(t *testing.T) {
	backlog := MaxPassesPerTick * window.DefaultBatch * 3
	store := newBacklogStore(backlog)

	closer := NewCloser(
		window.New(store), nothingStored{},
		FixedSettings{Value: Resolved{Keys: keys.DefaultSettings()}},
		mw.NewLogger("error", "json"))
	// The backlog needs three ticks' worth of claims. Under the old loop each of those
	// waited a full interval, so it could not finish before the second one — which is
	// what the deadline below distinguishes, and why the interval is a real wait rather
	// than a token one.
	const interval = 500 * time.Millisecond
	closer.interval = interval

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = closer.Run(ctx) }()

	// Drained by the first tick's catch-up loop, well inside the second interval. The
	// old loop would still be two ticks — one full second — from finishing here, and on
	// production's ten-second interval, half a minute.
	select {
	case <-store.drained:
	case <-time.After(interval * 2):
		t.Fatalf("%d of %d windows still scheduled after two intervals",
			store.remaining(), backlog)
	}
}
