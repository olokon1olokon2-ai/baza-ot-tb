PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_key TEXT NOT NULL UNIQUE,
  employee_name TEXT NOT NULL,
  position TEXT,
  employer TEXT,
  instruction_date TEXT,
  form_o86_value TEXT,
  form_086_value TEXT,
  has_medical_certificate INTEGER NOT NULL DEFAULT 0,
  slinger_certificate TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_employees_name ON employees(employee_name);
CREATE INDEX IF NOT EXISTS idx_employees_slinger ON employees(slinger_certificate);
