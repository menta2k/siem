ALTER TABLE normalized_events DROP INDEX IF EXISTS idx_linked_request_id;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS linked_request_id;
