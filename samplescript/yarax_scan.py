#!/usr/bin/env python3
"""
yarax_scan.py - YARA-X malware/threat scanner for the sanitizer-engine pipeline.

Usage (stdin mode - piped from shell):
    echo "$blob_b64" | base64 -d | python3 yarax_scan.py <rules_dir>

Usage (file mode):
    python3 yarax_scan.py <rules_dir> --file /path/to/file

Exit codes:
    0  - No threats detected (clean)
    1  - Threat(s) detected  (quarantine)
    2  - Scanner error
"""

import sys
import os
import json
import argparse
import glob


def load_rules(rules_dir: str):
    """
    Compile all .yar / .yara files from rules_dir.
    Prefers yara-x; falls back to yara-python if yara-x is not installed.
    Returns (compiled_rules, backend_name).
    """
    yar_files = (
        glob.glob(os.path.join(rules_dir, "*.yar"))
        + glob.glob(os.path.join(rules_dir, "*.yara"))
    )
    if not yar_files:
        print(f"[ERROR] No .yar/.yara rule files found in: {rules_dir}", file=sys.stderr)
        sys.exit(2)

    # Try yara-x first (preferred)
    try:
        import yara_x  # type: ignore
        compiler = yara_x.Compiler()
        for rule_file in sorted(yar_files):
            with open(rule_file, "r", encoding="utf-8", errors="replace") as fh:
                compiler.add_source(fh.read())
        return compiler.build(), "yara-x"
    except ImportError:
        pass

    # Fall back to classic yara-python
    try:
        import yara  # type: ignore
        rule_paths = {
            os.path.splitext(os.path.basename(f))[0]: f
            for f in sorted(yar_files)
        }
        return yara.compile(filepaths=rule_paths), "yara-python"
    except ImportError:
        pass

    print(
        "[ERROR] Neither 'yara_x' nor 'yara' Python packages are installed.\n"
        "        Install: pip install yara-x  OR  pip install yara-python",
        file=sys.stderr,
    )
    sys.exit(2)


def scan(rules, data: bytes, backend: str) -> list:
    """Scan bytes with compiled rules; return list of match dicts."""
    matches = []

    if backend == "yara-x":
        scanner = rules.scan(data)
        for m in scanner.matching_rules:
            entry = {
                "rule":      m.identifier,
                "namespace": getattr(m, "namespace", "default"),
                "tags":      list(getattr(m, "tags", [])),
                "meta":      dict(getattr(m, "metadata", {})),
                "strings":   [],
            }
            for pat in getattr(m, "patterns", []):
                for occ in getattr(pat, "matches", []):
                    entry["strings"].append({
                        "identifier": pat.identifier,
                        "offset":     occ.offset,
                        "length":     occ.length,
                    })
            matches.append(entry)

    else:  # yara-python
        for m in rules.match(data=data):
            entry = {
                "rule":      m.rule,
                "namespace": m.namespace,
                "tags":      list(m.tags),
                "meta":      dict(m.meta),
                "strings":   [],
            }
            for s in m.strings:
                instances = getattr(s, "instances", [])
                entry["strings"].append({
                    "identifier": s.identifier,
                    "offset":     instances[0].offset if instances else 0,
                    "length":     instances[0].length if instances else 0,
                })
            matches.append(entry)

    return matches


def main():
    parser = argparse.ArgumentParser(
        description="YARA-X scanner for the sanitizer-engine pipeline."
    )
    parser.add_argument("rules_dir", help="Directory containing .yar/.yara rule files")
    parser.add_argument("--file",    default=None, help="File to scan (default: stdin)")
    parser.add_argument("--json",    action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    rules, backend = load_rules(args.rules_dir)

    # Read data
    if args.file:
        try:
            with open(args.file, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"[ERROR] Cannot read file '{args.file}': {exc}", file=sys.stderr)
            sys.exit(2)
    else:
        data = sys.stdin.buffer.read()

    if not data:
        msg = "Empty data - nothing to scan."
        if args.json:
            print(json.dumps({"status": "clean", "matches": [], "message": msg}))
        else:
            print(f"[WARN] {msg}")
        sys.exit(0)

    # Scan
    try:
        matches = scan(rules, data, backend)
    except Exception as exc:
        print(f"[ERROR] Scan failed: {exc}", file=sys.stderr)
        sys.exit(2)

    # Report
    if matches:
        if args.json:
            print(json.dumps({
                "status":      "threat_detected",
                "backend":     backend,
                "match_count": len(matches),
                "matches":     matches,
            }, indent=2))
        else:
            print(f"[THREAT] YARA-X detected {len(matches)} match(es) (backend={backend}):")
            for m in matches:
                tags = ", ".join(m["tags"]) or "none"
                print(f"  Rule      : {m['rule']}")
                print(f"  Namespace : {m['namespace']}")
                print(f"  Tags      : {tags}")
                for k, v in m["meta"].items():
                    print(f"  Meta.{k:<10}: {v}")
                for s in m["strings"][:5]:
                    print(f"  String    : {s['identifier']} @ offset {s['offset']} (len={s['length']})")
                print()
        sys.exit(1)
    else:
        if args.json:
            print(json.dumps({"status": "clean", "backend": backend, "match_count": 0, "matches": []}))
        else:
            print(f"[CLEAN] No YARA-X rule matches. (backend={backend})")
        sys.exit(0)


if __name__ == "__main__":
    main()
