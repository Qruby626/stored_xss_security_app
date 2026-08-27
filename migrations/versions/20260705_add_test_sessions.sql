-- Migration: Add Test Sessions and session_id foreign keys
-- Date: 2026-07-05
-- Run this script against the application's MySQL database (stored_xss_security).
-- WARNING: DDL in MySQL may perform implicit commits. Run in a maintenance window.

-- 1. Create `test_sessions` table (if it doesn't exist)
CREATE TABLE IF NOT EXISTS test_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_name VARCHAR(150) NOT NULL,
    description TEXT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at DATETIME NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Ensure a legacy session exists so pre-existing logs can be assigned
--    This preserves historical data: we do not delete or null existing rows.
INSERT INTO test_sessions (session_name, description, started_at, status)
SELECT 'Legacy Session', 'Data migrated from before session management', NOW(), 'finished'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM test_sessions LIMIT 1);

-- Store the chosen legacy session id in a user variable
SET @legacy_session_id = (SELECT id FROM test_sessions ORDER BY id ASC LIMIT 1);

-- 3. Add session_id to `security_logs` (nullable first), assign legacy id for existing rows,
--    then make the column NOT NULL and add index + foreign key constraint.
ALTER TABLE security_logs
    ADD COLUMN session_id INT NULL AFTER id;

UPDATE security_logs
SET session_id = @legacy_session_id
WHERE session_id IS NULL;

ALTER TABLE security_logs
    MODIFY session_id INT NOT NULL,
    ADD INDEX ix_security_logs_session_id (session_id),
    ADD CONSTRAINT fk_security_logs_session
        FOREIGN KEY (session_id) REFERENCES test_sessions(id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- 4. Add session_id to `csp_reports` with the same safe procedure
ALTER TABLE csp_reports
    ADD COLUMN session_id INT NULL AFTER id;

UPDATE csp_reports
SET session_id = @legacy_session_id
WHERE session_id IS NULL;

ALTER TABLE csp_reports
    MODIFY session_id INT NOT NULL,
    ADD INDEX ix_csp_reports_session_id (session_id),
    ADD CONSTRAINT fk_csp_reports_session
        FOREIGN KEY (session_id) REFERENCES test_sessions(id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- 5. Optional: verify counts per session (examples)
-- SELECT session_id, COUNT(*) AS payloads FROM security_logs GROUP BY session_id;
-- SELECT session_id, COUNT(*) AS csp_reports FROM csp_reports GROUP BY session_id;

-- End of migration
