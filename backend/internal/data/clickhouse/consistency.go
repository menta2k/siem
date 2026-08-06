package clickhouse

import (
	"context"
	"fmt"
	"time"
)

// ConsistencyCheck reports duplicate-key violations in the control plane.
//
// This exists because of an accepted risk (research.md R6): ClickHouse has no unique
// constraints, so the control-plane tables enforce uniqueness with a Redis lock around
// a check-then-insert. That holds while the lock holds — it does not survive a Redis
// outage, a lock expiry under a long GC pause, or a manual insert.
//
// The risk was accepted rather than designed away because the alternative is a second
// datastore for four small tables. What makes it acceptable is DETECTION: a duplicate
// that nobody notices becomes two users who can both log in as the same address, or
// two feeds writing under one id. A nightly check turns a silent corruption into a
// report.
//
// It is read-only on purpose. Repairing a duplicate means choosing which row is real,
// and that is an operator's decision, not a background job's.
type ConsistencyCheck struct {
	client *Client
}

// NewConsistencyCheck constructs the checker.
func NewConsistencyCheck(client *Client) *ConsistencyCheck {
	return &ConsistencyCheck{client: client}
}

// Violation is one duplicate-key finding.
type Violation struct {
	Table string
	// Key is the value that should have been unique.
	Key string
	// Count is how many distinct rows share it.
	Count uint64
}

// Report is the outcome of one pass.
type Report struct {
	RanAt      time.Time
	Violations []Violation
}

// Clean reports whether the control plane holds no duplicates.
func (r Report) Clean() bool { return len(r.Violations) == 0 }

// uniquenessRules names each invariant the lock is supposed to hold.
//
// Written as explicit queries rather than generated from a schema, because the thing
// being checked is the INTENT — "an email is unique within a tenant" — and a generated
// check would only restate whatever the table already does, which is nothing.
var uniquenessRules = []struct {
	table string
	// query must return (key, count) for every group with more than one distinct row.
	query string
}{
	{
		table: "users",
		// FINAL first: without it, every ordinary update looks like a duplicate,
		// because a versioned row genuinely exists twice until the merge collapses it.
		query: `SELECT concat(toString(tenant_id), ':', lower(email)) AS k, count() AS n
		        FROM (SELECT DISTINCT tenant_id, user_id, email FROM users FINAL)
		        GROUP BY k HAVING n > 1`,
	},
	{
		table: "tenants",
		query: `SELECT lower(name) AS k, count() AS n
		        FROM (SELECT DISTINCT tenant_id, name FROM tenants FINAL)
		        GROUP BY k HAVING n > 1`,
	},
	{
		table: "feeds",
		// A feed's ingest token must map to exactly one feed. Two feeds sharing one
		// would let a vendor's deliveries land under the wrong tenant.
		query: `SELECT credential_ref AS k, count() AS n
		        FROM (SELECT DISTINCT tenant_id, feed_id, credential_ref FROM feeds FINAL)
		        WHERE credential_ref != ''
		        GROUP BY k HAVING n > 1`,
	},
}

// Run executes every uniqueness check.
//
// Deliberately unscoped by tenant: a duplicate that spans tenants is the most serious
// kind, and a per-tenant check could not see it.
func (c *ConsistencyCheck) Run(ctx context.Context) (Report, error) {
	report := Report{RanAt: time.Now().UTC()}

	for _, rule := range uniquenessRules {
		violations, err := c.check(ctx, rule.table, rule.query)
		if err != nil {
			return report, err
		}
		report.Violations = append(report.Violations, violations...)
	}
	return report, nil
}

func (c *ConsistencyCheck) check(ctx context.Context, table, query string) ([]Violation, error) {
	rows, err := c.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("consistency check on %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	var violations []Violation
	for rows.Next() {
		var (
			key   string
			count uint64
		)
		if err := rows.Scan(&key, &count); err != nil {
			return nil, fmt.Errorf("scan %s violation: %w", table, err)
		}
		violations = append(violations, Violation{Table: table, Key: key, Count: count})
	}
	return violations, rows.Err()
}
