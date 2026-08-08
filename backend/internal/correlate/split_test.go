package correlate_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	mw "github.com/menta2k/siem/internal/middleware"
)

// identityStore is countingWindowStore with SetNX and Get that actually REMEMBER.
//
// The shared harness stubs both — SetNX always claims and Get always returns nothing —
// which means identity never persists between close passes. That is precisely why the
// existing tests could not see a correlation id changing across passes, and why the
// split-record bug reached production.
type identityStore struct {
	countingWindowStore
	values map[string]string
}

func newIdentityStore() *identityStore {
	store := &identityStore{values: map[string]string{}}
	store.lists = map[string][]string{}
	store.zset = map[string]map[string]float64{}
	return store
}

func (s *identityStore) SetNX(
	_ context.Context, key, value string, _ time.Duration,
) (bool, error) {
	if _, taken := s.values[key]; taken {
		return false, nil
	}
	s.values[key] = value
	return true, nil
}

func (s *identityStore) Get(_ context.Context, key string) (string, error) {
	return s.values[key], nil
}

// Lookup mirrors the real client, where an ABSENT key is reported as not-found rather
// than raised as an error. The first version of this fix used Get, whose Redis
// implementation errors on a missing key — and since the stub returned an empty string
// instead, the tests passed while production failed every close pass.
func (s *identityStore) Lookup(_ context.Context, key string) (string, bool, error) {
	value, found := s.values[key]
	return value, found, nil
}

// The four rows a Worker-protected request produces, split by ARRIVAL time rather than
// by event time — which is the whole point. F5 and nginx ship in real time; Cloudflare
// Logpush lags roughly thirty seconds and only its origin-fetch row carries the bridge.
//
// The rays are chosen so the PARENT sorts BEFORE the origin fetch, reproducing the
// production case exactly: a281a225… < a281a226…, so the smallest-identifier rule flips
// the canonical key once the late rows widen the component.
const (
	splitParentRay = "a281a225b8e7d0e3" // P — client-facing request
	splitOriginRay = "a281a2261a7cd0e3" // Y — origin fetch, what F5 and nginx see
)

func splitEvent(t *testing.T, vendor, requestID, linked string, at time.Time) stream.Record {
	t.Helper()

	event := chdata.NormalizedEvent{
		TenantID: batchTenant, EventID: uuid.NewString(), Vendor: vendor,
		EventTime: at, VendorRequestID: requestID, LinkedRequestID: linked,
		ClientIP: net.ParseIP("203.0.113.10"), RequestHost: "www.jobs.bg",
		RequestPath: "/job/8557701", RequestMethod: "GET", Verdict: "allowed",
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return stream.Record{Key: []byte(event.EventID), Value: encoded}
}

// fileAndCloseOn files a batch and immediately closes everything it opened.
func fileAndCloseOn(
	t *testing.T, store *identityStore, records correlate.CorrelatedStore,
	batch []stream.Record,
) {
	t.Helper()

	worker := correlate.NewWorker(
		window.New(store),
		correlate.FixedSettings{Value: correlate.Resolved{Keys: keys.DefaultSettings()}},
		mw.NewLogger("error", "json"))
	if _, err := worker.HandleBatch(context.Background(), batch); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	closer := correlate.NewCloser(
		window.New(store), records,
		correlate.FixedSettings{Value: correlate.Resolved{Keys: keys.DefaultSettings()}},
		mw.NewLogger("error", "json"))
	if err := closer.Tick(context.Background(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("Tick: %v", err)
	}
}

// THE PRODUCTION SPLIT. One request became TWO permanent records, and 92.7% of
// f5+nginx records had a four-vendor twin because of it.
//
// F5 and nginx arrive first and know only the origin fetch's ray, so the group's
// canonical key — the smallest identifier in the component — is that ray. Cloudflare
// arrives thirty seconds later carrying the parent, the component widens, the canonical
// flips to the parent because it sorts first, and the amendment computes a DIFFERENT
// correlation id. The schema cannot supersede a row, so the first record is orphaned
// for the whole retention period.
//
// The id therefore has to be REMEMBERED under every identifier a request is known by,
// not recomputed from whichever events have turned up.
func TestALateBridgeAmendsTheRecordItDoesNotCreateASecondOne(t *testing.T) {
	store := newIdentityStore()
	records := &countingCorrelatedStore{}
	at := time.Now().UTC().Add(-time.Minute)

	// Real time: F5 and nginx, both seeing only the origin fetch's ray.
	fileAndCloseOn(t, store, records, []stream.Record{
		splitEvent(t, "f5", splitOriginRay, "", at),
		splitEvent(t, "nginx", splitOriginRay, "", at.Add(time.Second)),
	})

	if len(records.written) == 0 {
		t.Fatal("the first pass wrote nothing")
	}
	first := records.written[0].CorrelationID

	// Thirty seconds later: Cloudflare's client-facing row, its origin fetch carrying
	// the bridge, and DataDome's verdict on the parent.
	fileAndCloseOn(t, store, records, []stream.Record{
		splitEvent(t, "cloudflare", splitParentRay, "", at),
		splitEvent(t, "cloudflare", splitOriginRay, splitParentRay, at),
		splitEvent(t, "datadome", splitParentRay, "", at),
	})

	ids := map[uuid.UUID]bool{}
	for _, record := range records.written {
		ids[record.CorrelationID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("one request produced %d correlation ids, want 1 — the late rows wrote "+
			"a second record instead of amending the first, and the orphan is permanent",
			len(ids))
	}

	last := records.written[len(records.written)-1]
	if last.CorrelationID != first {
		t.Errorf("amendment landed on %s, want the original %s", last.CorrelationID, first)
	}
	if len(last.Vendors) != 4 {
		t.Errorf("final record has vendors %v, want all four", last.Vendors)
	}
}

// The same request in the OPPOSITE order — Cloudflare and DataDome first, F5 and nginx
// late — must also converge on one record. Arrival order is not something the platform
// controls, and a fix that only works one way round is not a fix.
func TestTheOrderOfArrivalDoesNotChangeTheRecord(t *testing.T) {
	store := newIdentityStore()
	records := &countingCorrelatedStore{}
	at := time.Now().UTC().Add(-time.Minute)

	fileAndCloseOn(t, store, records, []stream.Record{
		splitEvent(t, "cloudflare", splitParentRay, "", at),
		splitEvent(t, "cloudflare", splitOriginRay, splitParentRay, at),
		splitEvent(t, "datadome", splitParentRay, "", at),
	})
	if len(records.written) == 0 {
		t.Fatal("the first pass wrote nothing")
	}
	first := records.written[0].CorrelationID

	fileAndCloseOn(t, store, records, []stream.Record{
		splitEvent(t, "f5", splitOriginRay, "", at),
		splitEvent(t, "nginx", splitOriginRay, "", at.Add(time.Second)),
	})

	for _, record := range records.written {
		if record.CorrelationID != first {
			t.Fatalf("correlation id changed from %s to %s across arrival order",
				first, record.CorrelationID)
		}
	}
}

// Two genuinely different requests must not be merged by the aliasing. The identity is
// claimed per identifier, so a request sharing none of them keeps its own record.
func TestUnrelatedRequestsKeepSeparateIdentities(t *testing.T) {
	store := newIdentityStore()
	records := &countingCorrelatedStore{}
	at := time.Now().UTC().Add(-time.Minute)

	fileAndCloseOn(t, store, records, []stream.Record{
		splitEvent(t, "f5", splitOriginRay, "", at),
		splitEvent(t, "nginx", splitOriginRay, "", at),
	})
	fileAndCloseOn(t, store, records, []stream.Record{
		splitEvent(t, "f5", "b391c337c9f8e1f4", "", at),
		splitEvent(t, "nginx", "b391c337c9f8e1f4", "", at),
	})

	ids := map[uuid.UUID]bool{}
	for _, record := range records.written {
		ids[record.CorrelationID] = true
	}
	if len(ids) != 2 {
		t.Errorf("two unrelated requests produced %d correlation ids, want 2", len(ids))
	}
}
