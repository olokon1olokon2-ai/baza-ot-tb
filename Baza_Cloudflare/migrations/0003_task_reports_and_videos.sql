-- Фото- и видеоотчёты по заданиям
ALTER TABLE tasks ADD COLUMN completion_comment TEXT;
ALTER TABLE tasks ADD COLUMN submitted_at TEXT;
ALTER TABLE tasks ADD COLUMN completed_at TEXT;
ALTER TABLE tasks ADD COLUMN reviewed_by INTEGER REFERENCES users(id);
ALTER TABLE tasks ADD COLUMN reviewed_at TEXT;
ALTER TABLE tasks ADD COLUMN review_comment TEXT;

CREATE TABLE IF NOT EXISTS task_photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  photo_type TEXT NOT NULL CHECK(photo_type IN ('before','after')),
  uploaded_by INTEGER NOT NULL,
  file_key TEXT NOT NULL,
  content_type TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
  FOREIGN KEY(uploaded_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS task_videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  uploaded_by INTEGER NOT NULL,
  file_key TEXT NOT NULL,
  content_type TEXT NOT NULL,
  original_name TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
  FOREIGN KEY(uploaded_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_task_photos_task_id ON task_photos(task_id);
CREATE INDEX IF NOT EXISTS idx_task_videos_task_id ON task_videos(task_id);
CREATE TABLE IF NOT EXISTS task_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  old_status TEXT,
  new_status TEXT NOT NULL,
  comment TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_task_history_task_id ON task_history(task_id);
