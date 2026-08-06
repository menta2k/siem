package window

import (
	"strings"

	"github.com/google/uuid"
)

// The schedule is a single sorted set shared by every tenant, so each entry has to
// carry its own tenant. A set per tenant would be tidier to read but would force the
// poller to know the tenant list up front and to issue one call per tenant per tick,
// which does not hold at a few thousand tenants.
const scheduleSeparator = "\x00"

func encodeScheduled(tenantID uuid.UUID, key string) string {
	return tenantID.String() + scheduleSeparator + key
}

// decodeScheduled parses a schedule entry, reporting false for anything malformed.
//
// A bad entry is skipped rather than returned as an error: the schedule is a shared
// set, and one unparsable member must not stall every other tenant's correlation.
func decodeScheduled(value string) (Scheduled, bool) {
	tenantPart, key, found := strings.Cut(value, scheduleSeparator)
	if !found || key == "" {
		return Scheduled{}, false
	}
	tenantID, err := uuid.Parse(tenantPart)
	if err != nil {
		return Scheduled{}, false
	}
	return Scheduled{Key: key, TenantID: tenantID}, true
}
