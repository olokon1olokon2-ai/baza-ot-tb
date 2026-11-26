-- Group multiple images uploaded in one submission so an admin decision applies to all of them.
ALTER TABLE violation_photos ADD COLUMN submission_id TEXT;
CREATE INDEX IF NOT EXISTS idx_violation_photos_submission_id ON violation_photos(submission_id);
