// Package version carries the build identity stamped in at link time.
//
// It exists so an operator can answer "which build is this?" without guessing from a
// container tag. A SIEM is evidence infrastructure: when a correlation looks wrong, the
// first question is which version produced it, and a deployment that cannot answer that
// turns a five-minute check into an archaeology exercise.
//
// The values are set with -ldflags -X at build time. They are deliberately package
// variables rather than constants — a constant cannot be stamped.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// These are overridden at link time by the release build. The defaults are what a
// `go build` with no flags produces, and they say so rather than pretending to be a
// release: "dev" is a truthful answer, "0.0.0" is not.
var (
	// Version is the release version, without a leading "v".
	Version = "dev"
	// Commit is the short commit hash the build came from.
	Commit = "unknown"
	// Date is the RFC3339 build timestamp.
	Date = "unknown"
)

// Info is the build identity as a whole.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the current build identity.
//
// When the binary was not stamped — a local `go build`, or a `go install` from source —
// it falls back to the commit the Go toolchain embeds in the build info, so a developer
// build still identifies itself rather than reporting "unknown".
func Get() Info {
	commit := Commit
	if commit == "unknown" {
		commit = vcsRevision()
	}

	return Info{
		Version:   Version,
		Commit:    commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String renders the identity for a startup log line.
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s, %s)",
		i.Version, i.Commit, i.BuildDate, i.GoVersion, i.Platform)
}

// vcsRevision reads the commit the toolchain recorded, shortened to match the stamped
// form so the two sources cannot be told apart by their shape.
func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, setting := range info.Settings {
		if setting.Key != "vcs.revision" {
			continue
		}
		if len(setting.Value) > 7 {
			return setting.Value[:7]
		}
		return setting.Value
	}
	return "unknown"
}
