CREATE TABLE IF NOT EXISTS access_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER,
  target_user_id INTEGER,
  action TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (actor_id) REFERENCES users(id),
  FOREIGN KEY (target_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_access_audit_created_at ON access_audit(created_at);
