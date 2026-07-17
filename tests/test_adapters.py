"""
ForgeGuard — adapter tests.

Each scanner adapter is tested against known fixture data to ensure parsing
produces expected Finding objects with correct fields.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from security.models import Severity
from security.adapters import (
    ALL_ADAPTERS,
    BanditAdapter,
    CodeQLAdapter,
    GitleaksAdapter,
    GrypeAdapter,
    PipAuditAdapter,
    ZAPAdapter,
)


def _write_fixture(dir_path: Path, filename: str, data) -> Path:
    path = dir_path / filename
    path.write_text(json.dumps(data, indent=2))
    return path


# ── Bandit ─────────────────────────────────────────────────────────────

def test_bandit_adapter_parses_basic(tmp_path):
    adapter = BanditAdapter()
    data = {
        "results": [
            {
                "test_id": "B201",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "app/sqli.py",
                "line_number": 22,
                "col_offset": 4,
                "issue_text": "Possible SQL injection",
            }
        ]
    }
    _write_fixture(tmp_path, "bandit.json", data)
    result = adapter.parse(str(tmp_path))
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source == "bandit"
    assert f.rule_id == "B201"
    assert f.severity == Severity.HIGH
    assert f.file == "app/sqli.py"
    assert f.line == 22
    assert "CWE-89" in f.cwes  # B201 maps to CWE-89


def test_bandit_adapter_no_output(tmp_path):
    adapter = BanditAdapter()
    result = adapter.parse(str(tmp_path))
    assert result.error is not None
    assert "No bandit output found" in result.error


def test_bandit_severity_mapping():
    """Verify severity mappings are correct."""
    from security.adapters import _map_bandit_severity
    assert _map_bandit_severity("HIGH") == "high"
    assert _map_bandit_severity("MEDIUM") == "medium"
    assert _map_bandit_severity("LOW") == "low"
    assert _map_bandit_severity("unknown") == "low"  # fallback


# ── pip-audit ──────────────────────────────────────────────────────────

def test_pip_audit_adapter(tmp_path):
    adapter = PipAuditAdapter()
    data = {
        "dependencies": [
            {
                "name": "starlette",
                "version": "0.25.0",
                "vulnerabilities": [
                    {
                        "id": "GHSA-v5gw-mw7f-84px",
                        "severity": "HIGH",
                        "description": "Path traversal",
                        "aliases": [{"id": "CWE-22"}],
                        "fix_versions": ["0.27.0"],
                    }
                ],
            }
        ]
    }
    _write_fixture(tmp_path, "pip-audit.json", data)
    result = adapter.parse(str(tmp_path))
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source == "pip-audit"
    assert f.severity == Severity.HIGH
    assert f.fix_available is True


# ── CodeQL ─────────────────────────────────────────────────────────────

def test_codeql_adapter(tmp_path):
    adapter = CodeQLAdapter()
    data = {
        "runs": [{
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "SQL injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/sqli.py"},
                        "region": {"startLine": 22, "startColumn": 4},
                    }
                }],
                "properties": {"tags": ["CWE-89", "security"]},
            }],
        }]
    }
    _write_fixture(tmp_path, "codeql.sarif", data)
    result = adapter.parse(str(tmp_path))
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source == "codeql"
    assert f.severity == Severity.HIGH  # "error" level maps to high
    assert "CWE-89" in f.cwes


# ── Grype ──────────────────────────────────────────────────────────────

def test_grype_adapter(tmp_path):
    adapter = GrypeAdapter()
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-12345",
                    "severity": "Critical",
                    "description": "Critical DoS",
                    "fix": {"versions": ["2.0.1"]},
                },
                "artifact": {"name": "example-lib", "version": "1.0.0"},
            }
        ]
    }
    _write_fixture(tmp_path, "grype.json", data)
    result = adapter.parse(str(tmp_path))
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source == "grype"
    assert f.severity == Severity.CRITICAL
    assert f.fix_available is True


# ── ZAP ────────────────────────────────────────────────────────────────

def test_zap_adapter(tmp_path):
    adapter = ZAPAdapter()
    data = {
        "site": [{
            "alerts": [{
                "id": "10010",
                "name": "Cookie No HttpOnly Flag",
                "riskdesc": "Medium (Medium)",
                "risk": "Medium",
                "cweid": 1004,
                "instances": [{"uri": "http://localhost:8000/", "method": "GET"}],
            }],
        }]
    }
    _write_fixture(tmp_path, "zap.json", data)
    result = adapter.parse(str(tmp_path))
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source == "zap"
    assert "CWE-1004" in f.cwes


# ── Gitleaks ───────────────────────────────────────────────────────────

def test_gitleaks_adapter(tmp_path):
    adapter = GitleaksAdapter()
    data = [
        {
            "RuleID": "gh-credentials",
            "Severity": "high",
            "CWE": "CWE-798",
            "File": ".env",
            "StartLine": 1,
            "StartColumn": 0,
            "Description": "GitHub credentials detected",
        }
    ]
    _write_fixture(tmp_path, "gitleaks.json", data)
    result = adapter.parse(str(tmp_path))
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source == "gitleaks"
    assert f.severity == Severity.HIGH
    assert "CWE-798" in f.cwes


# ── All adapters ───────────────────────────────────────────────────────

def test_all_adapters_have_unique_names():
    """Each adapter should have a unique name."""
    names = [a.name for a in ALL_ADAPTERS]
    assert len(names) == len(set(names))


def test_each_adapter_handles_empty_dir(tmp_path):
    """Every adapter should gracefully handle a directory with no output."""
    for adapter in ALL_ADAPTERS:
        result = adapter.parse(str(tmp_path))
        assert result.error is not None, f"{adapter.name} should error on empty dir"
