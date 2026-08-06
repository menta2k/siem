package server

import (
	"encoding/json"
	"net/http"

	"github.com/menta2k/siem/internal/version"
)

// VersionHandler reports the running build.
//
// It carries no tenant data and no configuration — only the build identity — so it is
// safe on an unauthenticated operational port. Anything that would be a disclosure
// risk, such as which stores it is pointed at, belongs on /readyz behind the operator's
// own network boundary.
func VersionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(version.Get()); err != nil {
			// The status is already written by then, so there is nothing to send. The
			// caller sees a truncated body, which is the honest outcome.
			return
		}
	})
}
