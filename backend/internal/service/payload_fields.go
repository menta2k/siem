package service

import (
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
)

// payloadFields rebuilds the vendor-native fields of one event from its raw payload.
//
// These used to be stored columns. raw_extra was a parsed copy of bytes raw_events
// already keeps in full, and the copy cost four times the original — 12.79 GiB against
// 3.08 GiB — because a Map interleaves keys and values per row, while the payload column
// compresses whole blocks of structurally identical JSON together. unknown_fields rode on
// every search row for a signal nothing on that endpoint displayed.
//
// Recomputing here trades a per-row storage cost paid by every event ever ingested for one
// parse of one event, on a view an analyst opened deliberately.
//
// IT RETURNS NO ERROR BY DESIGN. Every failure degrades to empty rather than propagating:
// the caller has already loaded the normalized row and the raw payload, and both are
// returned beside this, so turning a
// detail view into an error because a payload no longer parses would withhold the answer
// over a decoration. That also covers the case retention creates — a row outliving the
// payload it came from.
func payloadFields(
	registry *vendors.Registry, vendor string, payload []byte, redactedFields []string,
) (map[string]string, []string) {
	if registry == nil || len(payload) == 0 {
		return nil, nil
	}

	adapter, err := registry.Get(vendor)
	if err != nil {
		return nil, nil
	}

	format, ok := adapter.Detect(payload)
	if !ok {
		return nil, nil
	}

	records, err := adapter.Parse(payload, format)
	if err != nil || len(records) == 0 {
		return nil, nil
	}

	event, err := adapter.Normalize(records[0])
	if err != nil {
		return nil, nil
	}

	// Re-applied, not skipped: the stored copy was masked before it was written, so
	// serving an unmasked rebuild would quietly undo the tenant's policy on exactly the
	// field they asked to hide.
	event = normalize.Redact(event, redactedFields)

	return event.RawExtra, event.UnknownFields
}
