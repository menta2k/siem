package alerting

import (
	"context"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// RepoStore adapts the ClickHouse repository to the evaluator's read surface.
//
// The adapter exists so the evaluator can be tested without a database, and so the
// GROUP BY columns cross the boundary as already-resolved names. The repository takes
// plain strings because that is what reaches SQL; the evaluator holds query.Column
// values because that is the type the allowlist produces. Converting here — in one
// place, after resolution — is what keeps an unresolved string from ever reaching a
// GROUP BY clause.
type RepoStore struct {
	repo *chdata.AlertingRepo
}

// NewRepoStore wraps a repository.
func NewRepoStore(repo *chdata.AlertingRepo) *RepoStore {
	return &RepoStore{repo: repo}
}

// Measure runs one rule's aggregate over its window.
func (s *RepoStore) Measure(ctx context.Context, q MeasureQuery) ([]Measurement, error) {
	groupBy := make([]string, 0, len(q.GroupBy))
	for _, column := range q.GroupBy {
		groupBy = append(groupBy, string(column))
	}

	measurements, err := s.repo.Measure(ctx, chdata.MeasureRequest{
		From:          q.Window.From,
		To:            q.Window.To,
		Aggregate:     string(q.Aggregate),
		Conditions:    q.Conditions,
		Args:          q.Args,
		GroupBy:       groupBy,
		EvidenceLimit: q.EvidenceLimit,
	})
	if err != nil {
		return nil, err
	}

	out := make([]Measurement, 0, len(measurements))
	for _, m := range measurements {
		out = append(out, Measurement{
			GroupValues:            m.GroupValues,
			Value:                  m.Value,
			Total:                  m.Total,
			EvidenceCorrelationIDs: m.EvidenceCorrelationIDs,
		})
	}
	return out, nil
}
