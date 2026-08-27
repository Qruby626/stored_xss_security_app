-- Safe Migration: Add `test_sessions` and make `security_logs` / `csp_reports` session-aware
-- File: sql/migration_add_test_sessions_safe.sql
-- Date: 2026-07-05
--
-- This script is non-destructive: it does not delete existing rows. It will:
--  1) Create `test_sessions` table if not present
--  2) Ensure at least one "legacy" session exists and stores its id in @legacy_session_id
--  3) Add `session_id` column (nullable) to `security_logs` and `csp_reports` if absent
--  4) Assign existing rows to the legacy session where session_id IS NULL
--  5) Alter `session_id` to NOT NULL and add indexes + foreign keys when safe
--
-- IMPORTANT: MySQL DDL statements may cause implicit commits. Run this script in a maintenance window.
-- Always take a backup before running this script (see README instructions).

-- -----------------------------------------------------------------------------
-- 1) Create test_sessions table if not exists
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS test_sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  session_name VARCHAR(150) NOT NULL,
  description TEXT NULL,
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ended_at DATETIME NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 2) Ensure a legacy session exists and capture its id
-- -----------------------------------------------------------------------------
-- If the table is empty, insert a legacy row so we can assign existing logs to it.
INSERT INTO test_sessions (session_name, description, started_at, status)
SELECT 'Legacy Session', 'Data migrated from before session management', NOW(), 'finished'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM test_sessions LIMIT 1);

-- Grab the canonical legacy session id (first row)
SET @legacy_session_id = (
  SELECT id FROM test_sessions ORDER BY id ASC LIMIT 1
);

-- -----------------------------------------------------------------------------
-- 3) Add session_id to security_logs (nullable), update existing rows, then make NOT NULL
-- -----------------------------------------------------------------------------
-- Add column if it doesn't exist (MySQL 8+ supports IF NOT EXISTS; older versions will ignore this and raise an error)
ALTER TABLE security_logs
  ADD COLUMN IF NOT EXISTS session_id INT NULL AFTER id;

-- Ensure any existing NULL session_id values are assigned to the legacy session
UPDATE security_logs
SET session_id = @legacy_session_id
WHERE session_id IS NULL;

-- If the column is still nullable, make it NOT NULL. If it already is NOT NULL this will be a no-op.
ALTER TABLE security_logs
  MODIFY COLUMN session_id INT NOT NULL;

-- Create index on session_id if it does not yet exist
SET @idx_exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'security_logs' AND index_name = 'ix_security_logs_session_id'
);

SET @sql = IF(@idx_exists = 0,
  'CREATE INDEX ix_security_logs_session_id ON security_logs (session_id)',
  'SELECT "index exists"'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add foreign key constraint if not present (using conditional prepared statement)
SET @fk_exists := (
  SELECT COUNT(*) FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE() AND table_name = 'security_logs' AND constraint_name = 'fk_security_logs_session'
);
SET @sql = IF(@fk_exists = 0,
  'ALTER TABLE security_logs ADD CONSTRAINT fk_security_logs_session FOREIGN KEY (session_id) REFERENCES test_sessions(id) ON DELETE RESTRICT ON UPDATE CASCADE',
  'SELECT "fk exists"'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 4) Add session_id to csp_reports (nullable), update existing rows, then make NOT NULL
-- -----------------------------------------------------------------------------
ALTER TABLE csp_reports
  ADD COLUMN IF NOT EXISTS session_id INT NULL AFTER id;

UPDATE csp_reports
SET session_id = @legacy_session_id
WHERE session_id IS NULL;

ALTER TABLE csp_reports
  MODIFY COLUMN session_id INT NOT NULL;

-- Create index on csp_reports.session_id if missing
SET @idx_exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'csp_reports' AND index_name = 'ix_csp_reports_session_id'
);

SET @sql = IF(@idx_exists = 0,
  'CREATE INDEX ix_csp_reports_session_id ON csp_reports (session_id)',
  'SELECT "index exists"'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add foreign key constraint if not present (using conditional prepared statement)
SET @fk_exists := (
  SELECT COUNT(*) FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE() AND table_name = 'csp_reports' AND constraint_name = 'fk_csp_reports_session'
);
SET @sql = IF(@fk_exists = 0,
  'ALTER TABLE csp_reports ADD CONSTRAINT fk_csp_reports_session FOREIGN KEY (session_id) REFERENCES test_sessions(id) ON DELETE RESTRICT ON UPDATE CASCADE',
  'SELECT "fk exists"'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 5) Final verification queries (non-destructive) — print counts per session
-- -----------------------------------------------------------------------------
-- Note: these SELECTs are informative; they do not modify data.
SELECT 'security_logs count per session' AS info;
SELECT session_id, COUNT(*) AS cnt FROM security_logs GROUP BY session_id ORDER BY session_id;

SELECT 'csp_reports count per session' AS info;
SELECT session_id, COUNT(*) AS cnt FROM csp_reports GROUP BY session_id ORDER BY session_id;

-- End of script
