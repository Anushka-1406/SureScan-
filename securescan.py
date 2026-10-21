"""
SecureScan - a simple scanner that finds hardcoded secrets in source code.

Usage:
    python securescan.py <folder>                 scan a folder
    python securescan.py <folder> --exclude test_samples
"""
import argparse
import json
import os
import re
import sys

# 1. WHAT to look for: each rule is a name, a regex pattern, and a severity.
RULES = [
    ("Hardcoded password", re.compile(r"""password\s*[=:]\s*["'][^"']+["']""", re.I), "HIGH"),
    ("Hardcoded API key", re.compile(r"""api[_-]?key\s*[=:]\s*["'][^"']+["']""", re.I), "HIGH"),
    ("Hardcoded secret/token", re.compile(r"""(secret|token)\s*[=:]\s*["'][^"']+["']""", re.I), "HIGH"),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "CRITICAL"),
]

# 2. WHERE to look: only these file types, and skip these folders.
EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".java", ".env", ".json", ".yml", ".yaml")
SKIP_FOLDERS = {".git", "node_modules", "venv", "__pycache__", "dist", "build"}


def scan_file(path):
    """Read one file line by line and return a list of findings."""
    findings = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for name, pattern, severity in RULES:
                    if pattern.search(line):
                        findings.append({
                            "file": path,
                            "line": line_number,
                            "issue": name,
                            "severity": severity,
                        })
    except OSError:
        pass  # skip files we cannot read
    return findings


def scan_folder(folder, exclude=()):
    """Walk through every folder and scan each matching file."""
    all_findings = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS and d not in exclude]
        for name in files:
            if name.endswith(EXTENSIONS):
                all_findings += scan_file(os.path.join(root, name))
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Scan code for hardcoded secrets")
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument("--exclude", nargs="*", default=[], help="folders to skip")
    parser.add_argument("--report", default="securescan_report.json", help="report file name")
    args = parser.parse_args()

    findings = scan_folder(args.folder, args.exclude)

    # 3. REPORT: print to screen and save as JSON.
    if findings:
        print(f"Found {len(findings)} possible secret(s):\n")
        for f in findings:
            print(f"[{f['severity']}] {f['file']}:{f['line']} -> {f['issue']}")
    else:
        print("No hardcoded secrets found.")

    with open(args.report, "w") as out:
        json.dump(findings, out, indent=2)
    print(f"\nReport saved to {args.report}")

    # 4. EXIT CODE: 1 means "failed". GitHub Actions turns the build red on 1.
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
