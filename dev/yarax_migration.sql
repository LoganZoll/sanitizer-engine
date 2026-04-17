-- yarax_migration.sql
-- Adds YARA-X scan result tracking to the sanitizer_db schema.
-- Run once after deploying job_yarax_processor.sh:
--   mysql -u user -ppassword sanitizer_db < dev/yarax_migration.sql

-- Allow new YARA-X statuses in job_request.status
-- (If status is an ENUM, add new values; otherwise this is already supported by VARCHAR)
-- ALTER TABLE job_request MODIFY COLUMN status VARCHAR(64) NOT NULL DEFAULT 'PENDING';

-- Table to store per-job YARA-X scan results
CREATE TABLE IF NOT EXISTS yarax_scan_result (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_request_id  INT UNSIGNED NOT NULL,
    scanned_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    backend         VARCHAR(32)  NOT NULL DEFAULT 'yara-x',
    status          VARCHAR(32)  NOT NULL COMMENT 'YARAX_CLEAN | YARAX_THREAT | YARAX_ERROR',
    match_count     INT          NOT NULL DEFAULT 0,
    -- JSON array of matched rule names (stored as text for broad MySQL version compat)
    matched_rules   TEXT         NULL,
    -- Full JSON scan output for audit purposes
    scan_output     MEDIUMTEXT   NULL,
    INDEX idx_job_request_id (job_request_id),
    INDEX idx_status          (status),
    INDEX idx_scanned_at      (scanned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
