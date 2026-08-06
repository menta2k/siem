package service

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// auditWriteFailures counts audit entries that could not be persisted.
//
// A failed audit write does not fail the request that was already authorized and
// carried out — losing the action AND its record is worse than losing only the
// record. But it must never be silent, so it is counted here and alerted on: a rising
// value means the audit trail has gaps and can no longer be trusted as evidence.
var auditWriteFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "siem_audit_write_failures_total",
	Help: "Audit entries that could not be persisted. Any sustained non-zero rate " +
		"means the audit trail is incomplete.",
})
