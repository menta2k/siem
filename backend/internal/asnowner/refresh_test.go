package asnowner_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/asnowner"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
)

// stubStore records what a refresh tried to write.
type stubStore struct {
	written []chdata.ASNOwner
	calls   int
	err     error
}

func (s *stubStore) Replace(_ context.Context, owners []chdata.ASNOwner, _ time.Time) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	s.written = owners
	return nil
}

func (s *stubStore) Count(context.Context) (uint64, error) { return uint64(len(s.written)), nil }

func gzipped(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatalf("gzip fixture: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	return buf.Bytes()
}

func testLog() mw.Logger { return mw.NewLogger("error", "json") }

// The happy path, over TLS because the worker refuses anything else.
func TestRefreshStoresWhatTheSourcePublished(t *testing.T) {
	body := gzipped(t, strings.Join([]string{
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
		"78.90.0.0\t78.90.255.255\t8866\tBG\tVIVACOM-AS",
	}, "\n"))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()

	store := &stubStore{}
	worker := asnowner.NewWorker(store, server.URL, time.Hour, testLog(),
		asnowner.WithHTTPClient(server.Client()))

	count, err := worker.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if len(store.written) != 2 || store.written[1].Name != "VIVACOM-AS" {
		t.Errorf("stored %+v, want both networks with their names", store.written)
	}
}

// Plain HTTP is refused. These names are read next to an ASN during an investigation,
// and over cleartext anyone on the path chooses them.
func TestRefreshRefusesPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipped(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET"))
	}))
	defer server.Close()

	store := &stubStore{}
	worker := asnowner.NewWorker(store, server.URL, time.Hour, testLog())

	if _, err := worker.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() accepted an http:// source")
	}
	if store.calls != 0 {
		t.Error("the store was written despite the source being rejected")
	}
}

// A failed download must leave the existing table alone. A stale name is worth more
// than an empty panel, and this is the case that decides which one you get.
func TestRefreshLeavesTheTableAloneWhenTheSourceFails(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"upstream error", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"not gzip", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>captive portal</html>"))
		}},
		{"empty body", func(http.ResponseWriter, *http.Request) {}},
		{"gzip holding nothing usable", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(gzipped(t, "0.0.0.0\t0.255.255.255\t0\tNone\tNot routed"))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tc.handler)
			defer server.Close()

			store := &stubStore{}
			worker := asnowner.NewWorker(store, server.URL, time.Hour, testLog(),
				asnowner.WithHTTPClient(server.Client()))

			if _, err := worker.Refresh(context.Background()); err == nil {
				t.Fatal("Refresh() reported success on a failed download")
			}
			if store.calls != 0 {
				t.Errorf("the store was written %d times; a failed download must not "+
					"replace the last good table", store.calls)
			}
		})
	}
}

func TestRefreshReportsAStoreFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipped(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET"))
	}))
	defer server.Close()

	store := &stubStore{err: errors.New("clickhouse unreachable")}
	worker := asnowner.NewWorker(store, server.URL, time.Hour, testLog(),
		asnowner.WithHTTPClient(server.Client()))

	if _, err := worker.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() hid a store failure")
	}
}

// A cancelled context must abandon the download rather than hold the shutdown open.
func TestRefreshHonoursContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	worker := asnowner.NewWorker(&stubStore{}, server.URL, time.Hour, testLog(),
		asnowner.WithHTTPClient(server.Client()))

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	if _, err := worker.Refresh(ctx); err == nil {
		t.Fatal("Refresh() ignored the cancelled context")
	}
}

func TestNewWorkerFallsBackToThePublishedDefaults(t *testing.T) {
	worker := asnowner.NewWorker(&stubStore{}, "", 0, testLog())

	if got := worker.Source(); got != asnowner.DefaultSourceURL {
		t.Errorf("source = %q, want the published default", got)
	}
	if got := worker.Interval(); got != asnowner.DefaultInterval {
		t.Errorf("interval = %v, want %v", got, asnowner.DefaultInterval)
	}
	if worker.Name() != "asn-owners" {
		t.Errorf("Name() = %q", worker.Name())
	}
}
