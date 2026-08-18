-- Nothing is lost with it: the index only decides how much of event_ids is read, never
-- what the query answers.
ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_event_ids
