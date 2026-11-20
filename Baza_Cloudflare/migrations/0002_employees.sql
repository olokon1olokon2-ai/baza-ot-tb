PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id TEXT NOT NULL,
  source_key TEXT NOT NULL,
  employee_name TEXT NOT NULL,
  position TEXT,
  employer TEXT,
  instruction_date TEXT,
  form_o86_value TEXT,
  form_086_value TEXT,
  has_medical_certificate INTEGER NOT NULL DEFAULT 0,
  slinger_certificate TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(batch_id, source_key)
);

CREATE TABLE IF NOT EXISTS employee_import_state (
  id INTEGER PRIMARY KEY CHECK(id=1),
  active_batch_id TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO employee_import_state(id, active_batch_id) VALUES(1, NULL);

CREATE INDEX IF NOT EXISTS idx_employees_name ON employees(employee_name);
CREATE INDEX IF NOT EXISTS idx_employees_batch ON employees(batch_id);
CREATE INDEX IF NOT EXISTS idx_employees_slinger ON employees(slinger_certificate);
