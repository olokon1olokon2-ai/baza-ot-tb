-- Store responsible access separately instead of changing the constrained role column.
-- Existing users and all foreign-key relationships remain untouched.
ALTER TABLE users ADD COLUMN is_responsible INTEGER NOT NULL DEFAULT 0 CHECK(is_responsible IN (0,1));
