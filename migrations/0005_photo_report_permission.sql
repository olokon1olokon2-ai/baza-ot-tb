ALTER TABLE users ADD COLUMN can_submit_photo_reports INTEGER NOT NULL DEFAULT 0 CHECK (can_submit_photo_reports IN (0,1));
