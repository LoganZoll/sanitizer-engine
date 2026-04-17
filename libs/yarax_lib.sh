#!/usr/bin/env bash
# yarax_lib.sh - Shell helper functions for YARA-X scanning in the sanitizer-engine pipeline.
#
# Source this file from the main processor scripts:
#   source "${SCRIPT_DIR}/libs/yarax_lib.sh"

: "${YARAX_RULES_DIR:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rules}"
: "${YARAX_SCRIPT:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/samplescript/yarax_scan.py}"
: "${STATUS_YARAX_CLEAN:=YARAX_CLEAN}"
: "${STATUS_YARAX_THREAT:=YARAX_THREAT}"
: "${STATUS_YARAX_ERROR:=YARAX_ERROR}"

# ---------------------------------------------------------------------------
# run_yarax_scan_b64 <base64_blob> <job_id>
#
# Decodes a base64 blob and pipes it to yarax_scan.py.
# Outputs the scanner's stdout.
# Returns:
#   0  - clean
#   1  - threat detected
#   2  - scan error
# ---------------------------------------------------------------------------
run_yarax_scan_b64() {
    local blob_b64="$1"
    local job_id="$2"

    if [[ -z "$blob_b64" ]]; then
        echo "[yarax_lib] Empty blob for job_id=${job_id}" >&2
        return 2
    fi

    local tmp_file
    tmp_file=$(mktemp /dev/shm/tmp_yarax_XXXXXX)
    # Ensure cleanup even if this function is interrupted
    trap 'rm -f "$tmp_file"' RETURN

    # Decode base64 to temp file
    if ! echo "$blob_b64" | base64 -d > "$tmp_file" 2>/dev/null; then
        echo "[yarax_lib] base64 decode failed for job_id=${job_id}" >&2
        return 2
    fi

    # Run scanner
    python3 "$YARAX_SCRIPT" "$YARAX_RULES_DIR" --file "$tmp_file"
    return $?
}

# ---------------------------------------------------------------------------
# run_yarax_scan_file <file_path>
#
# Scans an already-decoded file on disk.
# Returns the same exit codes as run_yarax_scan_b64.
# ---------------------------------------------------------------------------
run_yarax_scan_file() {
    local file_path="$1"

    if [[ ! -f "$file_path" ]]; then
        echo "[yarax_lib] File not found: ${file_path}" >&2
        return 2
    fi

    python3 "$YARAX_SCRIPT" "$YARAX_RULES_DIR" --file "$file_path"
    return $?
}
