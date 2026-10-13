#!/usr/bin/env python3
"""VeilCheck: local-first repository hygiene checks; no network or code execution."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
    "vendor", "coverage", ".tox",
}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".php",
    ".rb", ".sh", ".bash", ".ps1", ".yml", ".yaml", ".toml", ".ini",
    ".cfg", ".conf", ".json", ".xml", ".html", ".htm", ".css", ".env",
    ".properties", ".md", ".txt", ".sql", ".dockerfile",
}
MAX_FILE_BYTES = 1_000_000

RULES = [
    ("TLS_VERIFY_DISABLED", "high", re.compile(r"\bverify\s*=\s*False\b", re.I),
     "TLS certificate verification may be disabled."),
    ("UNVERIFIED_SSL_CONTEXT", "high",
     re.compile(r"\b_create_unverified_context\s*\("),
     "An unverified TLS context may accept invalid certificates."),
    ("DEBUG_ENABLED", "medium",
     re.compile(r"(?i)\b(?:debug|debug_mode)\s*[:=]\s*(?:True|true|1|['\"]true['\"])\b"),
     "A debug flag appears to be enabled."),
    ("SHELL_TRUE", "medium", re.compile(r"\bshell\s*=\s*True\b"),
     "Shell execution is enabled; review how command input is constructed."),
    ("HARDCODED_SECRET_LIKE", "high",
     re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)\b\s*[:=]\s*(['\"])(?!\s*(?:|changeme|example|your[_ -].*|<.*?>)\s*\1)[^'\"]{6,}\1"),
     "A credential-like value may be hard-coded; the value is redacted."),
    ("PRIVATE_KEY_BLOCK", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "A private-key PEM marker was found. Treat exposed private keys as compromised."),
]

def is_probably_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {
        "dockerfile", "makefile", ".env", ".env.local", ".env.production"
    }

def iter_files(root: Path, include_hidden: bool):
    for current, dirs, names in __import__("os").walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and (include_hidden or not d.startswith("."))
            and not (current_path / d).is_symlink()
        ]
        for name in names:
            path = current_path / name
            if path.is_symlink():
                continue
            if not include_hidden and name.startswith(".") and name not in {
                ".env", ".env.local", ".env.production"
            }:
                continue
            if is_probably_text(path):
                yield path

def scan(root: Path, include_hidden: bool = False) -> dict:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Target must be an existing directory.")
    findings = []
    scanned = 0
    skipped_large = 0

    for path in iter_files(root, include_hidden):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped_large += 1
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        for line_no, line in enumerate(content.splitlines(), 1):
            for rule_id, severity, pattern, description in RULES:
                match = pattern.search(line)
                if not match:
                    continue
                safe_excerpt = line.strip()
                # Avoid printing the suspected credential itself.
                if rule_id == "HARDCODED_SECRET_LIKE":
                    safe_excerpt = re.sub(
                        r"""(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)(\s*[:=]\s*)(['"])[^'"]*\3""",
                        r"\1\2\3[REDACTED]\3", safe_excerpt
                    )
                findings.append({
                    "rule": rule_id,
                    "severity": severity,
                    "file": path.relative_to(root).as_posix(),
                    "line": line_no,
                    "description": description,
                    "excerpt": safe_excerpt[:220],
                })

    return {
        "tool": "VeilCheck",
        "version": "1.0.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "files_scanned": scanned,
        "large_files_skipped": skipped_large,
        "finding_count": len(findings),
        "findings": findings,
        "notice": "Heuristic findings require manual review; absence of findings does not prove security.",
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Local-first repository hygiene scanner.")
    parser.add_argument("directory", help="directory you own or are authorized to review")
    parser.add_argument("--json", metavar="FILE", help="write full report to a JSON file")
    parser.add_argument("--include-hidden", action="store_true",
                        help="include hidden files/folders except skipped dependency folders")
    args = parser.parse_args()
    try:
        report = scan(Path(args.directory), args.include_hidden)
    except ValueError as exc:
        print(f"VeilCheck: {exc}", file=sys.stderr)
        return 2

    print(f"\nVeilCheck | Local Repository Review")
    print("=" * 42)
    print(f"Files scanned: {report['files_scanned']}")
    print(f"Findings:      {report['finding_count']}")
    print("-" * 42)
    if not report["findings"]:
        print("No matching patterns found. This is not a guarantee of security.")
    for item in report["findings"]:
        print(f"[{item['severity'].upper():8}] {item['rule']}  {item['file']}:{item['line']}")
        print(f"           {item['description']}")
        print(f"           {item['excerpt']}")
    print("\n", report["notice"])
    if args.json:
        output = Path(args.json)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON report: {output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
