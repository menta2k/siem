package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/menta2k/siem/internal/middleware"
)

// OFF UNLESS ASKED FOR is a security property, not a default worth changing casually.
// The ingest service's operational port is published to the host, so a profiling
// endpoint that came up on its own would put the heap — feed credentials and vendor
// payloads included — one bind-address mistake away from the internet.
func TestProfilingIsOffWithoutAnAddress(t *testing.T) {
	deps := &Deps{Log: middleware.NewLogger("error", "text")}
	if srv := StartProfiling(t.Context(), deps, ""); srv != nil {
		t.Fatalf("an empty PPROF_BIND started a listener on %q", srv.Addr)
	}
}

// Every profile the runtime offers has to be reachable, because the ones registered
// individually (profile, trace, symbol, cmdline) are exactly the ones pprof.Index does
// NOT serve — forgetting them yields a working index whose useful links all 404.
func TestProfilingServesEveryProfile(t *testing.T) {
	srv := ProfilingServer("127.0.0.1:0")

	// Deliberately not /profile or /trace: both block for their sampling duration, and
	// the point here is that the route is mounted, which the index and heap prove.
	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/allocs",
		"/debug/pprof/cmdline",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, path, nil)
			srv.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("GET %s = %d, want 200", path, rec.Code)
			}
		})
	}
}

// A CPU profile is a long, slow response by construction — `-seconds 60` holds the
// connection open for a full minute — so a write deadline would truncate precisely the
// profiles worth taking.
func TestProfilingHasNoWriteDeadline(t *testing.T) {
	if got := ProfilingServer("127.0.0.1:0").WriteTimeout; got != 0 {
		t.Errorf("WriteTimeout = %v, want none: it would cut off long CPU profiles", got)
	}
}
