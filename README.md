# SecureScan

A small Python tool that scans source code for hardcoded secrets (passwords, API keys, tokens, AWS keys, private keys) and saves a JSON report.

## Run
    python securescan.py <folder>
    python securescan.py . --exclude test_samples

## How it works
1. Walks through every folder and picks code/config files.
2. Reads each file line by line.
3. Matches each line against regex rules.
4. Prints findings with file, line number and severity, and saves `securescan_report.json`.
5. Exits with code 1 if anything is found, so GitHub Actions marks the build as failed.

## GitHub Actions
`.github/workflows/securescan.yml` runs the scan on every push and pull request.
## What it checks
1. Hardcoded secrets: regex scan (securescan.py)
2. Vulnerable dependencies: pip-audit and npm audit in the GitHub Actions pipeline

## Limitations
- Regex can give false positives and miss secrets that do not match a pattern.
- Next steps: entropy detection, dependency checks, pre-commit hook.
- Next steps: entropy detection, scanning git history, pre-commit hook.
