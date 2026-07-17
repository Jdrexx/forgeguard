#!/usr/bin/env python3
"""
ForgeGuard — create scanner fixture output for testing.

Generates mock JSON output for each supported scanner so the policy
engine can be exercised without running the actual scanners.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SCAN_FIXTURES = Path(__file__).resolve().parent / "scan-fixtures"


def bandit_fixture() -> dict:
    return {
        "results": [
            {
                "test_id": "B201",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "filename": "app/vulnerable/sqli.py",
                "line_number": 22,
                "col_offset": 4,
                "issue_text": "Possible SQL injection vector through string interpolation.",
                "code": "query = f\"SELECT ... WHERE id = '{user_id}'\"",
            },
            {
                "test_id": "B301",
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "filename": "app/vulnerable/traversal.py",
                "line_number": 18,
                "col_offset": 4,
                "issue_text": "Possible path traversal — user input used in file path.",
                "code": "filepath = os.path.join(BASE_DIR, filename)",
            },
            {
                "test_id": "B403",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "app/vulnerable/pickle_rce.py",
                "line_number": 15,
                "col_offset": 4,
                "issue_text": "Use of pickle.loads on user-supplied data — possible RCE.",
                "code": "obj = pickle.loads(decoded)",
            },
        ],
        "errors": [],
        "generated_at": "2026-01-01T00:00:00Z",
        "metrics": {
            "_totals": {"CONFIDENCE.HIGH": 2, "CONFIDENCE.MEDIUM": 1, "SEVERITY.HIGH": 1, "SEVERITY.MEDIUM": 2}
        },
    }


def pip_audit_fixture() -> dict:
    return {
        "dependencies": [
            {
                "name": "starlette",
                "version": "0.25.0",
                "vulnerabilities": [
                    {
                        "id": "GHSA-v5gw-mw7f-84px",
                        "severity": "HIGH",
                        "description": "Starlette has a path traversal vulnerability",
                        "aliases": [{"id": "CWE-22"}],
                        "fix_versions": ["0.27.0"],
                    }
                ],
            },
            {
                "name": "cryptography",
                "version": "39.0.0",
                "vulnerabilities": [
                    {
                        "id": "GHSA-x4qr-2fvf-3mr5",
                        "severity": "MEDIUM",
                        "description": "Vulnerable to NULL pointer dereference",
                        "aliases": [{"id": "CWE-476"}],
                        "fix_versions": ["41.0.0"],
                    }
                ],
            },
        ]
    }


def codeql_fixture() -> dict:
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "SQL query built from user-controlled sources"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/vulnerable/sqli.py"},
                                "region": {"startLine": 22, "startColumn": 4},
                            }
                        }],
                        "properties": {
                            "tags": ["CWE-89", "security"],
                            "severity": "error",
                        },
                    }
                ],
            }
        ]
    }


def grype_fixture() -> dict:
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-12345",
                    "severity": "High",
                    "namespace": "CWE-400",
                    "description": "Denial of service in example-lib",
                    "fix": {"versions": ["2.0.1"]},
                },
                "artifact": {
                    "name": "example-lib",
                    "version": "1.0.0",
                    "type": "python",
                },
            }
        ]
    }


def zap_fixture() -> dict:
    return {
        "site": [
            {
                "alerts": [
                    {
                        "id": "10010",
                        "name": "Cookie No HttpOnly Flag",
                        "riskdesc": "Medium (Medium)",
                        "risk": "Medium",
                        "cweid": 1004,
                        "instances": [{"uri": "http://localhost:8000/api/user", "method": "GET"}],
                    }
                ]
            }
        ]
    }


def gitleaks_fixture() -> list[dict]:
    return [
        {
            "RuleID": "gh-credentials",
            "Severity": "high",
            "CWE": "CWE-798",
            "File": "app/vulnerable/info_leak.py",
            "StartLine": 28,
            "StartColumn": 8,
            "Description": "Detected API key in environment dump",
        }
    ]


def generate_all(output_dir: str = "scan-fixtures"):
    """Generate fixture files for all scanners."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "bandit.json": bandit_fixture(),
        "pip-audit.json": pip_audit_fixture(),
        "codeql.sarif": codeql_fixture(),
        "grype.json": grype_fixture(),
        "zap.json": zap_fixture(),
        "gitleaks.json": gitleaks_fixture(),
    }

    for name, data in fixtures.items():
        path = out / name
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  ✓ {path}")

    print(f"\nDone. {len(fixtures)} fixture files written to {out}/")


if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "scan-fixtures"
    generate_all(output_dir)
