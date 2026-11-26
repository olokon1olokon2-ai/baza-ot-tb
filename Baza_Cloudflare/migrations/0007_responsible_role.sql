-- Add the responsible employee role while preserving existing user IDs and references.
PRAGMA defer_foreign_keys = ON;
CREATE TABLE users_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'engineer' CHECK(role IN ('admin','engineer','responsible')),
  organization_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
INSERT INTO users_new (id,username,full_name,password_hash,role,organization_id,active,created_at)
SELECT id,username,full_name,password_hash,role,organization_id,active,created_at FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
