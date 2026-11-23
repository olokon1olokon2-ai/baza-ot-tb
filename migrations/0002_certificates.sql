CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_name TEXT NOT NULL,
  position TEXT,
  certificate_number TEXT,
  valid_until TEXT NOT NULL,
  updated_by INTEGER,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users(id)
);

INSERT INTO certificates(employee_name,position,certificate_number,valid_until)
SELECT 'Джээнбеков Арслан Канатович','отделка','№ 433-09 от 15.09.2026','2026-12-15'
WHERE NOT EXISTS (
  SELECT 1 FROM certificates
  WHERE employee_name='Джээнбеков Арслан Канатович'
    AND certificate_number='№ 433-09 от 15.09.2026'
);
