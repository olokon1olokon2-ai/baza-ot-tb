PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS photo_reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 engineer_id INTEGER NOT NULL, organization_id INTEGER, description TEXT NOT NULL,
 file_key TEXT NOT NULL, content_type TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'На проверке' CHECK(status IN ('На проверке','Подтверждено','Отклонено')),
 review_comment TEXT NOT NULL DEFAULT '', reviewed_by INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT,
 FOREIGN KEY (engineer_id) REFERENCES users(id),
 FOREIGN KEY (organization_id) REFERENCES organizations(id),
 FOREIGN KEY (reviewed_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_photo_reports_engineer ON photo_reports(engineer_id,created_at);
CREATE INDEX IF NOT EXISTS idx_photo_reports_status ON photo_reports(status,created_at);