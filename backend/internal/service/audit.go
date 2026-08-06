package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/audit"
	"github.com/menta2k/siem/internal/auth"
)

// AuditWriter is the append-only trail every privileged action is recorded in.
type AuditWriter interface {
	Append(ctx context.Context, record audit.Record) (audit.Entry, error)
}

// recordAudit stamps the acting user and source address onto a record and appends it.
//
// Shared rather than reimplemented per service, because the actor is the part most
// easily left out: a trail that records WHAT happened but not WHO did it looks
// complete in review and answers nothing during an investigation.
//
// A write failure increments a counter instead of failing the caller's operation. The
// alternative is worse in both directions — refusing a successful action because its
// audit row could not be written turns an observability fault into an outage, and the
// counter is alerted on, so the gap does not pass unnoticed.
func recordAudit(ctx context.Context, log AuditWriter, r audit.Record) {
	if claims, ok := auth.ClaimsFromContext(ctx); ok {
		r.ActorEmail = claims.Email
		if id, err := uuid.Parse(claims.Subject); err == nil {
			r.ActorUserID = &id
		}
	}
	r.SourceIP = sourceIP(ctx)

	if _, err := log.Append(ctx, r); err != nil {
		auditWriteFailures.Inc()
	}
}
