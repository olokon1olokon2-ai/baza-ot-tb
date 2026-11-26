-- Extend the existing SQLite role constraint without rebuilding the users table
-- or disturbing foreign-key references from sessions, tasks, documents and audit rows.
PRAGMA writable_schema = ON;
UPDATE sqlite_schema
SET sql = replace(
  sql,
  "CHECK(role IN ('admin','engineer'))",
  "CHECK(role IN ('admin','engineer','responsible'))"
)
WHERE type='table'
  AND name='users'
  AND instr(sql, "CHECK(role IN ('admin','engineer'))") > 0;
PRAGMA writable_schema = OFF;
PRAGMA schema_version = 1000;
