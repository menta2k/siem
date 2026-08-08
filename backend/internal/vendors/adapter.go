// Package vendor holds the per-vendor log adapters behind one interface.
//
// Each vendor speaks its own dialect; this package is where those dialects become the
// common event model that makes cross-vendor correlation possible. Adding a fourth
// vendor should mean adding a directory here, not changing the pipeline.
package vendors

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Format identifies how a payload is encoded.
type Format string

// The payload encodings the platform accepts.
const (
	FormatJSON    Format = "json"   // a single object, or an array of them
	FormatNDJSON  Format = "ndjson" // newline-delimited objects
	FormatCEF     Format = "cef"    // ArcSight Common Event Format, used by F5
	FormatSyslog  Format = "syslog" // RFC3164/5424 with a key=value payload
	FormatUnknown Format = "unknown"
)

// Vendor names, matching the `vendor` column and the API enum.
const (
	Cloudflare = "cloudflare"
	F5         = "f5"
	DataDome   = "datadome"
)

// Verdict values, matching the normalized `verdict` column.
//
// Monitored is deliberately distinct from Allowed: a vendor in monitoring mode did
// not choose to allow the request, and conflating them would manufacture false
// disagreements against a vendor that genuinely blocked.
const (
	VerdictAllowed     = "allowed"
	VerdictBlocked     = "blocked"
	VerdictChallenged  = "challenged"
	VerdictRateLimited = "rate_limited"
	VerdictMonitored   = "monitored"
	VerdictUnknown     = "unknown"
)

// Score kinds.
const (
	ScoreKindBot    = "bot"
	ScoreKindThreat = "threat"
	ScoreKindNone   = "none"
)

// ErrUnparseable indicates a payload the adapter cannot read at all. The caller
// dead-letters it with a reason rather than dropping it (FR-006).
var ErrUnparseable = errors.New("vendor: payload could not be parsed")

// RawRecord is one event as extracted from a batch, before normalization. The bytes
// are retained so the original payload can be stored verbatim (FR-005).
type RawRecord struct {
	// Bytes is the exact slice this record occupied in the delivery.
	Bytes []byte
	// Fields is the decoded representation, if the format has one.
	Fields map[string]any
	// Format records how the record was encoded.
	Format Format
}

// Event is the common model: three vendor vocabularies under one set of names.
type Event struct {
	Vendor          string
	VendorAccount   string
	VendorRequestID string
	// VendorEventID is the vendor's own reference for its record of the request,
	// distinct from the identifier shared between vendors. F5's support_id.
	VendorEventID     string
	EventTime         time.Time
	EventTimeOriginal string

	ClientIP       net.IP
	ClientIPShared bool
	ClientASN      uint32
	ClientCountry  string

	RequestHost   string
	RequestPath   string
	RequestQuery  string
	RequestMethod string
	UserAgent     string
	HTTPStatus    uint16

	Verdict       string
	VerdictReason string
	RuleID        string
	RuleIDs       []string
	Score         *float32
	ScoreKind     string

	// RawExtra keeps vendor fields with no common-model home (FR-010).
	RawExtra map[string]string
	// UnknownFields names incoming keys the adapter did not recognize, which drives
	// the schema-drift warning (FR-012).
	UnknownFields []string
}

// Adapter converts one vendor's deliveries into common-model events.
//
// Implementations must satisfy four contract obligations, each covered by a fixture
// test in the vendor's package:
//
//  1. Parse never panics on arbitrary bytes. Enforced by a fuzz test.
//  2. A record missing an optional field normalizes successfully with that field
//     empty; it is not rejected.
//  3. Unknown incoming fields are preserved into RawExtra and reported in
//     UnknownFields. They never fail the batch.
//  4. Normalize is pure and deterministic: same input, same output, no clock and no
//     network. This is what makes replay-based correlation testing meaningful.
type Adapter interface {
	// Vendor returns the vendor name this adapter handles.
	Vendor() string
	// Detect identifies the payload encoding, reporting false when unrecognized.
	Detect(payload []byte) (Format, bool)
	// Parse splits a delivery into individual records.
	Parse(payload []byte, format Format) ([]RawRecord, error)
	// Normalize maps one record onto the common model.
	Normalize(record RawRecord) (Event, error)
}

// Registry resolves adapters by vendor name.
type Registry struct {
	adapters map[string]Adapter
}

// NewRegistry builds a registry from the given adapters.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{adapters: make(map[string]Adapter, len(adapters))}
	for _, a := range adapters {
		name := a.Vendor()
		if _, exists := registry.adapters[name]; exists {
			return nil, fmt.Errorf("vendor: duplicate adapter registered for %q", name)
		}
		registry.adapters[name] = a
	}
	return registry, nil
}

// Get returns the adapter for a vendor.
func (r *Registry) Get(vendorName string) (Adapter, error) {
	a, ok := r.adapters[strings.ToLower(vendorName)]
	if !ok {
		return nil, fmt.Errorf("vendor: no adapter for %q", vendorName)
	}
	return a, nil
}

// Vendors lists the registered vendor names.
func (r *Registry) Vendors() []string {
	names := make([]string, 0, len(r.adapters))
	for name := range r.adapters {
		names = append(names, name)
	}
	return names
}
