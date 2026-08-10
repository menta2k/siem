package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/pprof"
	"time"
)

// ProfilingServer serves Go's runtime profiles on their own listener.
//
// IT GETS ITS OWN LISTENER FOR A SECURITY REASON, not a tidiness one. The operational
// listener is PUBLISHED for siem-ingest — the compose file maps host 8001 to it so
// vendors can deliver — so anything mounted there is reachable from the internet.
// /debug/pprof/heap returns the contents of the heap, which at any moment holds feed
// credentials, vendor payloads and whatever else is in flight; /debug/pprof/profile
// pins a CPU for its whole duration and is a denial of service by design. Neither
// belongs on a port a stranger can reach.
//
// DISABLED BY DEFAULT for the same reason: it starts only when PPROF_BIND is set. The
// documented value is 127.0.0.1:6060, which inside a container means the profiles are
// reachable through `docker exec` and nowhere else — an operator who wants them opts
// in, takes the profile, and takes the setting back out.
//
// It exists because the alternative is guessing. Every performance question about this
// platform so far has been answered by reading code and reasoning about round trips,
// which is how you end up optimising the thing that was never the bottleneck. Thirty
// seconds of CPU profile settles it.
func ProfilingServer(addr string) *http.Server {
	mux := http.NewServeMux()

	// Index covers the profiles that need no handler of their own (heap, goroutine,
	// allocs, block, mutex); the other three are registered individually because
	// pprof.Index only serves them by name under its own path prefix.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// NO WriteTimeout. A CPU profile is a long, slow response by construction —
		// `go tool pprof -seconds 60` holds the connection open for the full minute —
		// and a write deadline would truncate exactly the profiles worth taking.
		IdleTimeout: 60 * time.Second,
	}
}

// StartProfiling runs the profiling listener when one is configured.
//
// It reports whether anything was started, so a caller knows whether it has a server to
// shut down. A profiling listener that fails to bind is logged and otherwise ignored:
// it is a diagnostic, and refusing to start the service because its debug port was
// taken would turn an observability gap into an outage.
func StartProfiling(ctx context.Context, deps *Deps, addr string) *http.Server {
	if addr == "" {
		return nil
	}

	srv := ProfilingServer(addr)
	go func() {
		deps.Log.Info(ctx, "profiling endpoints listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			deps.Log.Error(ctx, "profiling server stopped", "cause", err.Error())
		}
	}()
	return srv
}
