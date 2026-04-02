#!/bin/bash
# insert_csv_into_job_request.sh — Insert any CSV into job_request correctly

CSV_FILE=$1
TABLE="job_request"

if [ -z "$CSV_FILE" ]; then
  echo "Usage: $0 <csv_file>"
  exit 1
fi

if [ ! -f "$CSV_FILE" ]; then
  echo "File not found: $CSV_FILE"
  exit 1
fi

B64_CONTENT=$(base64 < "$CSV_FILE" | tr -d '\n')

FILE_NAME="$(basename "$CSV_FILE")"
USER_ID=1
STATUS="PENDING"
FILE_TYPE="csv"
REQUEST_TYPE="upload"
PRIORITY="normal"
CONTENT_TYPE="text/csv"

SQL="INSERT INTO $TABLE (file_content, file_content_content_type, status, file_type, request_type, priority, file_name, user_id)
VALUES (FROM_BASE64('$B64_CONTENT'), '$CONTENT_TYPE', '$STATUS', '$FILE_TYPE', '$REQUEST_TYPE', '$PRIORITY', '$FILE_NAME', $USER_ID);"

docker exec -i mysql_sanitizer mysql -u user -ppassword sanitizer_db -e "$SQL"

echo "Inserted $CSV_FILE into $TABLE"

