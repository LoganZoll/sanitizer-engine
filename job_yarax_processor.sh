#!/bin/bash
# job_yarax_processor.sh
# Polls job_request for PENDING jobs and runs YARA-X scan on each file blob.
# Mirrors the pattern of job_entropy_processor.sh.

set -o pipefail

# --- Configuration ---
: "${DB_HOST:=localhost}"
: "${DB_PORT:=3306}"
: "${DB_USER:=user}"
: "${DB_PASSWORD:=password}"
: "${DB_NAME:=sanitizer_db}"
: "${POLL_INTERVAL:=5}"
: "${PENDING_STATUS:=PENDING}"
: "${STATUS_YARAX_CLEAN:=YARAX_CLEAN}"
: "${STATUS_YARAX_THREAT:=YARAX_THREAT}"
: "${STATUS_YARAX_ERROR:=YARAX_ERROR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=libs/yarax_lib.sh
source "${SCRIPT_DIR}/libs/yarax_lib.sh"

trap 'rm -f /dev/shm/tmp_yarax_*' EXIT

# --- Database helper ---
mysql_exec() {
    local sql="$1"
    mysql -N -B \
        -h "$DB_HOST" \
        -P "$DB_PORT" \
        -u "$DB_USER" \
        -p"$DB_PASSWORD" \
        -D "$DB_NAME" \
        -e "$sql"
}

# --- Process one pending job ---
# Returns 0 if a job was processed, 1 if the queue was empty.
process_pending_job() {
    local records
    records=$(mysql_exec \
        "SELECT id, TO_BASE64(file_blob) FROM job_request WHERE status='${PENDING_STATUS}' LIMIT 1") \
        || return 1

    [[ -z "$records" ]] && return 1

    local job_id blob_b64
    IFS=$'\t' read -r job_id blob_b64 <<< "$records"
    [[ -z "$job_id" ]] && return 1

    echo "[yarax] Processing job_id=${job_id}"

    # Mark as in-progress
    mysql_exec "UPDATE job_request SET status='YARAX_SCANNING' WHERE id=${job_id};"

    local scan_output
    scan_output=$(run_yarax_scan_b64 "$blob_b64" "$job_id")
    local rc=$?

    echo "$scan_output"

    case $rc in
        0)  # Clean
            mysql_exec "UPDATE job_request SET status='${STATUS_YARAX_CLEAN}' WHERE id=${job_id};"
            mysql_exec "INSERT INTO job_execution_log (job_request_id, status, message)
                        VALUES (${job_id}, '${STATUS_YARAX_CLEAN}',
                        'YARA-X scan passed - no threats detected');"
            echo "[yarax] job_id=${job_id} -> CLEAN"
            ;;
        1)  # Threat detected
            mysql_exec "UPDATE job_request SET status='${STATUS_YARAX_THREAT}' WHERE id=${job_id};"
            mysql_exec "INSERT INTO job_execution_log (job_request_id, status, message)
                        VALUES (${job_id}, '${STATUS_YARAX_THREAT}',
                        'YARA-X scan THREAT detected - job quarantined');"
            echo "[yarax] job_id=${job_id} -> THREAT DETECTED"
            ;;
        *)  # Error
            mysql_exec "UPDATE job_request SET status='${STATUS_YARAX_ERROR}' WHERE id=${job_id};"
            mysql_exec "INSERT INTO job_execution_log (job_request_id, status, message)
                        VALUES (${job_id}, '${STATUS_YARAX_ERROR}',
                        'YARA-X scan error - see stderr');"
            echo "[yarax] job_id=${job_id} -> ERROR (rc=${rc})" >&2
            ;;
    esac

    return 0
}

# --- Main loop ---
echo "[*] Starting YARA-X Processor (poll interval: ${POLL_INTERVAL}s)..."
echo "[*] Rules dir : ${YARAX_RULES_DIR}"
echo "[*] DB        : ${DB_HOST}:${DB_PORT}/${DB_NAME}"

while true; do
    if ! process_pending_job; then
        echo "[*] No pending jobs. Sleeping ${POLL_INTERVAL}s..."
        sleep "$POLL_INTERVAL"
    fi
done
