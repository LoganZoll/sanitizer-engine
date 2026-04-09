#!/bin/bash
set -euo pipefail
set -o pipefail

FILE="samplefiles/eicar_test.txt"
DB_NAME="sanitizer_db"
PRIORITY="1"
USER_ID="2"
FILE_NAME="$(basename "$FILE")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=../libs/db_lib.sh
source "${SCRIPT_DIR}/libs/db_lib.sh"
source "${SCRIPT_DIR}/libs/kafka_lib.sh"
source "${SCRIPT_DIR}/libs/san_lib.sh"

## the following line are for testing purposes, it should be removed once the test is over
## or it should be moved to a separate test script

# Encode file once
echo "[INFO] Encoding file: $FILE"
B64_DATA="$(base64 < "$FILE" | tr -d '\n')"
echo "[INFO] File encoded successfully."

# Insert job request
echo "[INFO] Inserting job request into database..."
insert_job_request "$B64_DATA"
echo "[INFO] Job request inserted."

#end of testing code, the following lines should be in the main script to continuously read from the database and process the job requests

# Read only the latest PENDING job request
echo "[INFO] Reading latest PENDING job request from database..."
ROW="$(read_latest_pending_job_request)"

if [[ -z "$ROW" ]]; then
  echo "[ERROR] No PENDING rows found in job_request." >&2
  exit 1
fi
echo "[INFO] PENDING job request found."

IFS=$'\t' read -r JOB_ID FILE_NAME CONTENT_TYPE FILE_CONTENT_B64 <<< "$ROW"

# Update status to SANITIZING
update_job_request_status "$JOB_ID" "$STATUS_SANITIZING"
echo "[INFO] Updated job_request.id=${JOB_ID} status to $STATUS_SANITIZING"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZING" "Job id=${JOB_ID} status updated to $STATUS_SANITIZING"

# Validate blob content
if [[ -z "${FILE_CONTENT_B64:-}" ]]; then
  echo "[WARN] Empty blob content for job_request.id=${JOB_ID}" >&2
  update_job_request_status "$JOB_ID" "$STATUS_COMPLETED_WITH_WARNINGS"
  insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_COMPLETED_WITH_WARNINGS" "Empty blob content for job_request.id=${JOB_ID}"
  exit 1
fi

echo "[INFO] job_id=${JOB_ID} file_name=${FILE_NAME} content_type=${CONTENT_TYPE}"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZING" "Processing file=${FILE_NAME} content_type=${CONTENT_TYPE}"

# Sanitize
echo "[INFO] Starting sanitization..."
sanitized_msg="$(sanitize_base64 "$FILE_CONTENT_B64" "$JOB_ID" "$CONTENT_TYPE")"
echo "[INFO] Sanitized message: $sanitized_msg"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZED" "Sanitization complete for job_request.id=${JOB_ID}"

# Build the message and publish to Kafka Sanitizer Input Topic
echo "[INFO] Building Kafka message..."
json_message="$(build_message \
  "$sanitized_msg" \
  "$INPUT_TOPIC" \
  "$MESSAGE_ORIGIN" \
  "$MESSAGE_SOURCE" \
  "$MESSAGE_TYPE" \
  "$JOB_ID" \
  "$CONTENT_TYPE" \
  "$FILE_NAME")"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZED" "Kafka message built for topic=$INPUT_TOPIC"

echo "[INFO] Publishing message to topic: $INPUT_TOPIC"
publish_message "$INPUT_TOPIC" "$json_message"
echo "[INFO] Published message to topic: $INPUT_TOPIC"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZED" "Message published to topic=$INPUT_TOPIC origin=$MESSAGE_ORIGIN source=$MESSAGE_SOURCE type=$CONTENT_TYPE"

# Log message meta
echo "[INFO] Message meta: origin=$MESSAGE_ORIGIN, source=$MESSAGE_SOURCE, type=$CONTENT_TYPE"
echo "[INFO] Pretty-printed message:"
pretty_print_message "$json_message"

# Final status update
update_job_request_status "$JOB_ID" "$STATUS_AI_PROCESSING_PENDING"
echo "[INFO] Updated job_request.id=${JOB_ID} status to $STATUS_AI_PROCESSING_PENDING"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_AI_PROCESSING_PENDING" "Job id=${JOB_ID} handed off to AI processing."#!/bin/bash
set -euo pipefail
set -o pipefail

FILE="samplescript/2-csv-20260316221533.csv"
DB_NAME="sanitizer_db"
PRIORITY="1"
USER_ID="2"
FILE_NAME="$(basename "$FILE")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=../libs/db_lib.sh
source "${SCRIPT_DIR}/libs/db_lib.sh"
source "${SCRIPT_DIR}/libs/kafka_lib.sh"
source "${SCRIPT_DIR}/libs/san_lib.sh"

## the following line are for testing purposes, it should be removed once the test is over
## or it should be moved to a separate test script

# Encode file once
echo "[INFO] Encoding file: $FILE"
B64_DATA="$(base64 < "$FILE" | tr -d '\n')"
echo "[INFO] File encoded successfully."

# Insert job request
echo "[INFO] Inserting job request into database..."
insert_job_request "$B64_DATA"
echo "[INFO] Job request inserted."

#end of testing code, the following lines should be in the main script to continuously read from the database and process the job requests

# Read only the latest PENDING job request
echo "[INFO] Reading latest PENDING job request from database..."
ROW="$(read_latest_pending_job_request)"

if [[ -z "$ROW" ]]; then
  echo "[ERROR] No PENDING rows found in job_request." >&2
  exit 1
fi
echo "[INFO] PENDING job request found."

IFS=$'\t' read -r JOB_ID FILE_NAME CONTENT_TYPE FILE_CONTENT_B64 <<< "$ROW"

# Update status to SANITIZING
update_job_request_status "$JOB_ID" "$STATUS_SANITIZING"
echo "[INFO] Updated job_request.id=${JOB_ID} status to $STATUS_SANITIZING"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZING" "Job id=${JOB_ID} status updated to $STATUS_SANITIZING"

# Validate blob content
if [[ -z "${FILE_CONTENT_B64:-}" ]]; then
  echo "[WARN] Empty blob content for job_request.id=${JOB_ID}" >&2
  update_job_request_status "$JOB_ID" "$STATUS_COMPLETED_WITH_WARNINGS"
  insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_COMPLETED_WITH_WARNINGS" "Empty blob content for job_request.id=${JOB_ID}"
  exit 1
fi

echo "[INFO] job_id=${JOB_ID} file_name=${FILE_NAME} content_type=${CONTENT_TYPE}"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZING" "Processing file=${FILE_NAME} content_type=${CONTENT_TYPE}"

# Sanitize
echo "[INFO] Starting sanitization..."
sanitized_msg="$(sanitize_base64 "$FILE_CONTENT_B64" "$JOB_ID" "$CONTENT_TYPE")"
echo "[INFO] Sanitized message: $sanitized_msg"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZED" "Sanitization complete for job_request.id=${JOB_ID}"

# Build the message and publish to Kafka Sanitizer Input Topic
echo "[INFO] Building Kafka message..."
json_message="$(build_message \
  "$sanitized_msg" \
  "$INPUT_TOPIC" \
  "$MESSAGE_ORIGIN" \
  "$MESSAGE_SOURCE" \
  "$MESSAGE_TYPE" \
  "$JOB_ID" \
  "$CONTENT_TYPE" \
  "$FILE_NAME")"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZED" "Kafka message built for topic=$INPUT_TOPIC"

echo "[INFO] Publishing message to topic: $INPUT_TOPIC"
publish_message "$INPUT_TOPIC" "$json_message"
echo "[INFO] Published message to topic: $INPUT_TOPIC"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_SANITIZED" "Message published to topic=$INPUT_TOPIC origin=$MESSAGE_ORIGIN source=$MESSAGE_SOURCE type=$CONTENT_TYPE"

# Log message meta
echo "[INFO] Message meta: origin=$MESSAGE_ORIGIN, source=$MESSAGE_SOURCE, type=$CONTENT_TYPE"
echo "[INFO] Pretty-printed message:"
pretty_print_message "$json_message"

# Final status update
update_job_request_status "$JOB_ID" "$STATUS_AI_PROCESSING_PENDING"
echo "[INFO] Updated job_request.id=${JOB_ID} status to $STATUS_AI_PROCESSING_PENDING"
insert_execution_report "$JOB_ID" "$USER_ID" "$STATUS_AI_PROCESSING_PENDING" "Job id=${JOB_ID} handed off to AI processing."#!/bin/bash
set -euo pipefail
set -o pipefail

FILE="samplescript/2-csv-20260316221533.csv"
DB_NAME="sanitizer_db"
PRIORITY="1"
USER_ID="2"
FILE_NAME="$(basename "$FILE")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../libs/db_lib.sh
source "${SCRIPT_DIR}/libs/db_lib.sh"
source "${SCRIPT_DIR}/libs/kafka_lib.sh"
source "${SCRIPT_DIR}/libs/san_lib.sh"

## the following line are for testing purposes, it should be removed once the test is over
## or it should be moved to a separate test script
# Encode file once
B64_DATA="$(base64 < "$FILE" | tr -d '\n')"

# there should be echo statement here to log the progress to the logs
insert_job_request "$B64_DATA"
#end of testing code, the following lines should be in the main script to continuously read from the database and process the job requests

# Read the latest job request. In final product, it should only reading pending requests.

ROW="$(read_latest_job_request)"

if [[ -z "$ROW" ]]; then
  echo "No rows found in job_request" >&2
  exit 1
fi

# at this line, the status should be updated to SANITIZING

IFS=$'\t' read -r JOB_ID FILE_NAME CONTENT_TYPE FILE_CONTENT_B64 <<< "$ROW"

if [[ -z "${FILE_CONTENT_B64:-}" ]]; then
  echo "Empty blob content for job_request.id=${JOB_ID}" >&2
  # The job request should be updated to COMPLETED_WITH_WARNINGS if the blob content is empty.
  update_job_request_status "$JOB_ID" "$STATUS_COMPLETED_WITH_WARNINGS"
  # the job execution log should be updated to include the warning message about empty blob content.
fi

echo "job_id=${JOB_ID} file_name=${FILE_NAME} content_type=${CONTENT_TYPE}"
sanitized_msg="$(sanitize_base64 "$FILE_CONTENT_B64" "$JOB_ID" "$CONTENT_TYPE")"
echo "Sanitized message: $sanitized_msg"
# Build the message and publish to Kafka Sanitizer Input Topic

json_message="$(build_message \
  "$sanitized_msg" \
  "$INPUT_TOPIC" \
  "$MESSAGE_ORIGIN" \
  "$MESSAGE_SOURCE" \
  "$MESSAGE_TYPE" \
  "$JOB_ID" \
  "$CONTENT_TYPE" \
  "$FILE_NAME")"

publish_message "$INPUT_TOPIC" "$json_message"

echo "Published message to topic: $INPUT_TOPIC"
# also log the message meta information such as timestamp, origin,  etc.
echo "Message meta: origin=$MESSAGE_ORIGIN, source=$MESSAGE_SOURCE, type=$CONTENT_TYPE"
echo "Pretty-printed message:"
pretty_print_message "$json_message"

update_job_request_status "$JOB_ID" "$STATUS_AI_PROCESSING_PENDING"
echo "Updated job_request.id=${JOB_ID} status to $STATUS_AI_PROCESSING_PENDING"
