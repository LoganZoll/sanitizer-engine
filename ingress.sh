#!/bin/bash
# ingress.sh — Read latest job_request from MySQL and send to Kafka as JSON

DB_CONTAINER="mysql_sanitizer"
DB_USER="user"
DB_PASS="password"
DB_NAME="sanitizer_db"
TABLE="job_request"
TOPIC="sanitizer_in"

ROW=$(docker exec -i $DB_CONTAINER mysql -u $DB_USER -p$DB_PASS $DB_NAME -sN -e \
  "SELECT file_content, file_name FROM $TABLE ORDER BY id DESC LIMIT 1;")

if [[ -z "$ROW" ]]; then
  echo "No job_request found."
  exit 1
fi

IFS=$'\t' read -r FILE_CONTENT FILE_NAME <<< "$ROW"

# Decode the blob (assuming it was stored as base64 in file_content)
# If it's raw blob, skip base64 decode
# FILE_CONTENT=$(echo "$FILE_CONTENT" | base64 -d)

JSON=$(jq -n \
  --arg content "$FILE_CONTENT" \
  --arg file_name "$FILE_NAME" \
  --arg user "logan" \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg source "ingress" \
  '{
    file_name: $file_name,
    file_content: $content,
    user: $user,
    timestamp: $timestamp,
    source: $source
  }')

echo "$JSON" | docker exec -i dev_kafka_1 kafka-console-producer \
  --bootstrap-server localhost:9092 \
