package retention

import (
	"context"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// Repos adapts the two repositories retention spans into one store.
//
// Retention crosses events and correlated records, which live in separate
// repositories because they are separate concerns everywhere else. Joining them here
// rather than widening either one keeps the coupling in the package that actually
// needs both.
type Repos struct {
	Events     *chdata.EventRepo
	Correlated *chdata.CorrelatedRepo
}

// DeleteEventsBefore removes events past the retention window.
func (r Repos) DeleteEventsBefore(
	ctx context.Context, tenantID uuid.UUID, before time.Time,
) error {
	return r.Events.DeleteEventsBefore(ctx, tenantID, before)
}

// DeleteCorrelatedBefore removes correlated records past the retention window.
func (r Repos) DeleteCorrelatedBefore(
	ctx context.Context, tenantID uuid.UUID, before time.Time,
) error {
	return r.Correlated.DeleteCorrelatedBefore(ctx, tenantID, before)
}

// DeleteEventsInRange performs an explicit, audited purge.
func (r Repos) DeleteEventsInRange(
	ctx context.Context, tenantID uuid.UUID, from, to time.Time,
) error {
	return r.Events.DeleteEventsInRange(ctx, tenantID, from, to)
}
