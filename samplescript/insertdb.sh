#!/bin/bash
set -euo pipefail
set -o pipefail

FILE="2-csv-20260316221533.csv"
DB_NAME="sanitizer_db"
PRIORITY="1"
USER_ID="2"
FILE_NAME="$(basename "$FILE")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=../libs/db_lib.sh
source "${SCRIPT_DIR}/../libs/db_lib.sh"

# ── Step 1: Sanitize the file ─────────────────────────────────────────────────
echo "[INFO] Starting IP sanitization on file: $FILE"
sed -i '' 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[MASKED_IP]/g' "$FILE"
echo "[INFO] IP sanitization complete."

# ── Step 2: Encode file ───────────────────────────────────────────────────────
echo "[INFO] Encoding file to base64..."
B64_DATA="$(base64 < "$FILE" | tr -d '\n')"
echo "[INFO] Encoding complete."

# ── Step 3: Insert job request ────────────────────────────────────────────────
echo "[INFO] Inserting job request into database..."
insert_job_request "$B64_DATA"
echo "[INFO] Job request inserted."

# ── Step 4: Read latest PENDING job request ───────────────────────────────────
echo "[INFO] Reading latest PENDING job request..."
ROW="$(read_latest_pending_job_request)"

if [[ -z "$ROW" ]]; then
  echo "[ERROR] No PENDING rows found in job_request." >&2
  exit 1
fi

IFS=$'\t' read -r JOB_ID FILE_NAME CONTENT_TYPE FILE_CONTENT_B64 <<< "$ROW"
echo "[INFO] Found job_request: id=${JOB_ID} file_name=${FILE_NAME} content_type=${CONTENT_TYPE}"
insert_execution_report "$JOB_ID" "$USER_ID" "IN_PROGRESS" "Found PENDING job_request id=${JOB_ID}, file=${FILE_NAME}"

# ── Step 5: Validate blob content ─────────────────────────────────────────────
if [[ -z "${FILE_CONTENT_B64:-}" ]]; then
  echo "[ERROR] Empty blob content for job_request.id=${JOB_ID}" >&2
  insert_execution_report "$JOB_ID" "$USER_ID" "FAILED" "Empty blob content for job_request id=${JOB_ID}"
  exit 1
fi
echo "[INFO] Blob content validated for job_request.id=${JOB_ID}"
insert_execution_report "$JOB_ID" "$USER_ID" "IN_PROGRESS" "Blob content validated successfully."

# ── Step 6: Decode blob to output file ────────────────────────────────────────
echo "[INFO] Decoding blob content to test_output.csv..."
printf '%s' "$FILE_CONTENT_B64" | openssl base64 -d -A > test_output.csv
echo "[INFO] Blob content written to test_output.csv"
insert_execution_report "$JOB_ID" "$USER_ID" "IN_PROGRESS" "Decoded blob written to test_output.csv"

# ── Step 7: Mark job as COMPLETED ─────────────────────────────────────────────
echo "[INFO] Updating job_request.id=${JOB_ID} status to COMPLETED..."
update_job_request_status "$JOB_ID" "COMPLETED"
echo "[INFO] Updated job_request.id=${JOB_ID} status to COMPLETED."
insert_execution_report "$JOB_ID" "$USER_ID" "COMPLETED" "Job id=${JOB_ID} marked COMPLETED successfully."

# ── Step 8: Cleanup ───────────────────────────────────────────────────────────
echo "[INFO] Deleting job_request.id=${JOB_ID}..."
delete_job_request_by_id "$JOB_ID"
echo "[INFO] Deleted job_request.id=${JOB_ID}"
insert_execution_report "$JOB_ID" "$USER_ID" "COMPLETED" "Job id=${JOB_ID} deleted from job_request table. Process complete."

echo "[DONE] Job ${JOB_ID} processing finished."
echo "${JOB_ID}"#!/bin/bash
set -euo pipefail
set -o pipefail

FILE="2-csv-20260316221533.csv"
DB_NAME="sanitizer_db"
PRIORITY="1"
USER_ID="2"
FILE_NAME="$(basename "$FILE")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../libs/db_lib.sh
source "${SCRIPT_DIR}/../libs/db_lib.sh"


# Run your aiSanitizerEngine logic (e.g., masking IPs)
sed -i '' 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[MASKED_IP]/g' "$FILE"

# Encode file once
B64_DATA="$(base64 < "$FILE" | tr -d '\n')"

insert_job_request "$B64_DATA"

ROW="$(read_latest_job_request)"

if [[ -z "$ROW" ]]; then
  echo "No rows found in job_request" >&2
  exit 1
fi

IFS=$'\t' read -r JOB_ID FILE_NAME CONTENT_TYPE FILE_CONTENT_B64 <<< "$ROW"

if [[ -z "${FILE_CONTENT_B64:-}" ]]; then
  echo "Empty blob content for job_request.id=${JOB_ID}" >&2
  exit 1
fi

echo "job_id=${JOB_ID} file_name=${FILE_NAME} content_type=${CONTENT_TYPE}"

printf '%s' "$FILE_CONTENT_B64" | openssl base64 -d -A > test_output.csv
echo "Blob content written to test_output.csv"


update_job_request_status "$JOB_ID" "COMPLETED"
echo "Updated job_request.id=${JOB_ID} status to COMPLETED"


delete_job_request_by_id "$JOB_ID"
echo "Deleted job_request.id=${JOB_ID}"

echo ${JOB_ID}
