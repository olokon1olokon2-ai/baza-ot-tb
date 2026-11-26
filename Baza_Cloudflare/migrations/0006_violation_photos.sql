-- Закрытые фото нарушений: загрузка ответственными, проверка администратором.
CREATE TABLE IF NOT EXISTS violation_photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uploaded_by INTEGER NOT NULL,
  file_key TEXT NOT NULL,
  content_type TEXT NOT NULL,
  original_name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'На проверке' CHECK(status IN ('На проверке','Принято')),
  reviewed_by INTEGER,
  reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(uploaded_by) REFERENCES users(id),
  FOREIGN KEY(reviewed_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_violation_photos_uploaded_by ON violation_photos(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_violation_photos_status ON violation_photos(status);
