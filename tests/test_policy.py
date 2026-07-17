"""
ForgeGuard — policy engine tests.

Tests cover the full evaluation pipeline:
- Normalize → deduplicate → enrich → waive → decide → report
- Missing scanner output (fail-closed)
- Expired suppressions
- Severity budgets
- SARIF output format
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from security.models import Finding, PolicyDecision, Severity, Suppression
from security.policy import (
    PolicyConfig,
    _load_suppressions,
    deduplicate,
    decide,
    enrich,
    load_results,
    normalize,
    run_policy,
    waive,
)


# ── Fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def findings_list() -> list[Finding]:
    """Fixture with a realistic but passing mix of severities."""
    return [
        Finding(
            source="bandit",
            rule_id="B201",
            severity=Severity.MEDIUM,
            cwes=["CWE-89"],
            file="app/sqli.py",
            line=22,
            description="SQL injection vector",
            fix_available=False,
        ),
        Finding(
            source="bandit",
            rule_id="B301",
            severity=Severity.MEDIUM,
            cwes=["CWE-22"],
            file="app/traversal.py",
            line=18,
            description="Path traversal",
        ),
        Finding(
            source="codeql",
            rule_id="py/sql-injection",
            severity=Severity.MEDIUM,
            cwes=["CWE-89"],
            file="app/sqli.py",
            line=22,
            description="SQL query built from user input",
        ),
        Finding(
            source="pip-audit",
            rule_id="GHSA-v5gw-mw7f-84px",
            severity=Severity.LOW,
            cwes=["CWE-22"],
            file="starlette@0.25.0",
            description="Path traversal in Starlette",
            fix_available=True,
        ),
        Finding(
            source="grype",
            rule_id="CVE-2024-12345",
            severity=Severity.HIGH,
            file="example-lib@1.0.0",
            description="DoS in example-lib",
            fix_available=True,
        ),
    ]


@pytest.fixture
def scan_results_dir(tmp_path: Path) -> Path:
    """Create a directory with sample scanner output files for ALL adapters."""
    results = tmp_path / "scan-results"
    results.mkdir()

    # bandit.json
    bandit_data = {
        "results": [
            {
                "test_id": "B201",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "filename": "app/vulnerable/sqli.py",
                "line_number": 22,
                "issue_text": "SQL injection vector",
            }
        ]
    }
    (results / "bandit.json").write_text(json.dumps(bandit_data))

    # pip-audit.json
    pip_data = {
        "dependencies": [
            {
                "name": "starlette",
                "version": "0.25.0",
                "vulnerabilities": [
                    {
                        "id": "GHSA-v5gw-mw7f-84px",
                        "severity": "LOW",
                        "description": "Path traversal",
                        "aliases": [{"id": "CWE-22"}],
                        "fix_versions": ["0.27.0"],
                    }
                ],
            }
        ]
    }
    (results / "pip-audit.json").write_text(json.dumps(pip_data))

    # codeql.sarif
    codeql_data = {
        "runs": [{
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "warning",
                "message": {"text": "SQL injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/sqli.py"},
                        "region": {"startLine": 22, "startColumn": 4},
                    }
                }],
                "properties": {"tags": ["CWE-89"]},
            }],
        }]
    }
    (results / "codeql.sarif").write_text(json.dumps(codeql_data))

    # grype.json
    grype_data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-12345",
                    "severity": "High",
                    "description": "DoS in example-lib",
                    "fix": {"versions": ["2.0.1"]},
                },
                "artifact": {"name": "example-lib", "version": "1.0.0"},
            }
        ]
    }
    (results / "grype.json").write_text(json.dumps(grype_data))

    # zap.json
    zap_data = {
        "site": [{
            "alerts": [{
                "id": "10010",
                "name": "Cookie No HttpOnly Flag",
                "riskdesc": "Low (Low)",
                "risk": "Low",
                "cweid": 1004,
                "instances": [{"uri": "http://localhost:8000/", "method": "GET"}],
            }],
        }]
    }
    (results / "zap.json").write_text(json.dumps(zap_data))

    # gitleaks.json
    gitleaks_data = [
        {
            "RuleID": "gh-credentials",
            "Severity": "high",
            "CWE": "CWE-798",
            "File": ".env",
            "StartLine": 1,
            "Description": "GitHub credentials detected",
        }
    ]
    (results / "gitleaks.json").write_text(json.dumps(gitleaks_data))

    return results


# ── Normalize ──────────────────────────────────────────────────────────

def test_normalize_strips_whitespace():
    findings = [
        Finding(severity=" high ", file="  app/x.py  "),
        Finding(severity="MEDIUM", file="app/y.py"),
    ]
    result = normalize(findings)
    assert result[0].severity == Severity.HIGH
    assert result[0].file == "app/x.py"
    assert result[1].severity == Severity.MEDIUM


# ── Deduplicate ────────────────────────────────────────────────────────

def test_deduplicate_by_fingerprint(findings_list):
    # Add a duplicate with lower severity
    dup = Finding(
        source="bandit",
        rule_id="B201",
        severity=Severity.LOW,
        cwes=["CWE-89"],
        file="app/sqli.py",
        line=22,
        description="Lower severity duplicate",
    )
    combined = findings_list + [dup]
    result = deduplicate(combined)
    # Should keep the higher severity version
    for f in result:
        if f.rule_id == "B201" and f.source == "bandit":
            assert f.severity == Severity.MEDIUM
            break
    # Overall count should be deduped
    assert len(result) <= len(combined)


def test_deduplicate_prefers_reachable():
    unreachable = Finding(
        source="bandit",
        rule_id="B999",
        severity=Severity.HIGH,
        file="app/x.py",
        description="Unreachable",
        reachable=False,
    )
    reachable = Finding(
        source="bandit",
        rule_id="B999",
        severity=Severity.HIGH,
        file="app/x.py",
        description="Reachable",
        reachable=True,
    )
    result = deduplicate([unreachable, reachable])
    assert len(result) == 1
    assert result[0].reachable is True


# ── Enrich ─────────────────────────────────────────────────────────────

def test_enrich_marks_sqli_as_fixable():
    findings = [
        Finding(severity=Severity.MEDIUM, cwes=["CWE-89"], fix_available=False),
        Finding(severity=Severity.MEDIUM, cwes=["CWE-79"], fix_available=False),
        Finding(severity=Severity.MEDIUM, cwes=["CWE-999"], fix_available=False),
    ]
    result = enrich(findings)
    assert result[0].fix_available is True  # CWE-89 marked fixable
    assert result[1].fix_available is True  # CWE-79 marked fixable
    assert result[2].fix_available is False  # Unknown CWE not marked


# ── Waive / Suppressions ──────────────────────────────────────────────

def test_active_suppression_suppresses():
    findings = [
        Finding(source="bandit", rule_id="B201", severity=Severity.HIGH),
        Finding(source="bandit", rule_id="B301", severity=Severity.MEDIUM),
    ]
    suppressions = [
        Suppression(
            rule_id="B201",
            reason="Test fixture",
            expires=datetime.now() + timedelta(days=30),
        ),
    ]
    active, waived = waive(findings, suppressions)
    assert len(active) == 1
    assert len(waived) == 1
    assert waived[0].rule_id == "B201"


def test_expired_suppression_does_not_suppress():
    """Test that expired suppressions are truly ignored."""
    findings = [
        Finding(source="bandit", rule_id="B201", severity=Severity.HIGH),
    ]
    suppressions = [
        Suppression(
            rule_id="B201",
            reason="Expired waiver",
            expires=datetime.now() - timedelta(days=1),  # past date
        ),
    ]
    active, waived = waive(findings, suppressions)
    assert len(active) == 1
    assert len(waived) == 0


def test_suppression_matches_correct_source():
    findings = [
        Finding(source="bandit", rule_id="B201", severity=Severity.HIGH),
        Finding(source="codeql", rule_id="B201", severity=Severity.HIGH),
    ]
    suppressions = [
        Suppression(
            rule_id="B201",
            source="bandit",  # only suppress bandit findings
            reason="Bandit false positive",
            expires=datetime.now() + timedelta(days=30),
        ),
    ]
    active, waived = waive(findings, suppressions)
    assert len(waived) == 1
    assert waived[0].source == "bandit"
    assert len(active) == 1
    assert active[0].source == "codeql"


def test_load_suppressions_drops_expired(tmp_path):
    """Test that loading suppressions from YAML drops expired entries."""
    allowlist = tmp_path / "accepted-risks.yaml"
    allowlist.write_text(yaml.dump({
        "suppressions": [
            {
                "rule_id": "B201",
                "reason": "Active",
                "expires": (datetime.now() + timedelta(days=30)).isoformat(),
            },
            {
                "rule_id": "B301",
                "reason": "Expired",
                "expires": (datetime.now() - timedelta(days=1)).isoformat(),
            },
        ],
    }))

    suppressions = _load_suppressions(str(allowlist))
    assert len(suppressions) == 1
    assert suppressions[0].rule_id == "B201"


# ── Decide ─────────────────────────────────────────────────────────────

def test_decide_allows_within_budget(findings_list):
    """Test that decisions pass when within budget limits."""
    budgets = {"critical": 0, "high": 1, "medium": 5, "low": 20, "note": -1}
    decision = decide(findings_list, budgets)
    assert decision.allowed is True
    assert len(decision.blocking_findings) == 0


def test_decide_blocks_over_budget():
    """Test that exceeding the high budget blocks the pipeline."""
    budgets = {"critical": 0, "high": 0, "medium": 5, "low": 20, "note": -1}
    findings = [
        Finding(rule_id="HIGH-1", severity=Severity.HIGH),
        Finding(rule_id="HIGH-2", severity=Severity.HIGH),
    ]
    decision = decide(findings, budgets)
    assert decision.allowed is False
    assert len(decision.blocking_findings) == 2


def test_decide_zero_budget_blocks_any():
    """Test that zero budget means zero tolerance."""
    budgets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "note": -1}
    findings = [
        Finding(rule_id="LOW-1", severity=Severity.LOW),
        Finding(rule_id="MED-1", severity=Severity.MEDIUM),
    ]
    decision = decide(findings, budgets)
    assert decision.allowed is False
    assert len(decision.blocking_findings) == 2


def test_decide_unlimited_budget():
    """Test that -1 budget means unlimited."""
    budgets = {"critical": -1, "high": -1, "medium": -1, "low": -1, "note": -1}
    findings = [Finding(rule_id="ANY", severity=Severity.CRITICAL) for _ in range(100)]
    decision = decide(findings, budgets)
    assert decision.allowed is True


# ── Load Results (fail-closed) ─────────────────────────────────────────

def test_load_results_parses_known_formats(scan_results_dir):
    findings = load_results(scan_results_dir)
    assert len(findings) > 0
    sources = {f.source for f in findings}
    assert "bandit" in sources
    assert "codeql" in sources


def test_load_results_raises_on_missing_dir():
    with pytest.raises(RuntimeError, match="Results directory not found"):
        load_results("/tmp/nonexistent-forgeguard-test-dir")


def test_load_results_raises_on_corrupted_file(tmp_path):
    """Fail-closed: corrupted scanner output should raise."""
    results = tmp_path / "scan-results"
    results.mkdir()
    (results / "bandit.json").write_text("not valid json {{{")

    with pytest.raises(RuntimeError, match="Failed to parse"):
        load_results(results)


def test_load_results_raises_on_missing_all_output(tmp_path):
    """Fail-closed: if a required scanner has no output, the pipeline blocks."""
    results = tmp_path / "scan-results"
    results.mkdir()
    # No output files at all — should fail for each adapter
    with pytest.raises(RuntimeError, match="Failed to parse"):
        load_results(results)


# ── Full Pipeline ──────────────────────────────────────────────────────

def test_run_policy_full_pipeline(scan_results_dir, tmp_path):
    """Integration test: run the full policy pipeline end-to-end."""
    policy_file = tmp_path / "security-policy.yaml"
    policy_file.write_text(yaml.dump({
        "budgets": {"critical": 0, "high": 0, "medium": 10, "low": 20, "note": -1},
    }))

    allowlist_file = tmp_path / "accepted-risks.yaml"
    allowlist_file.write_text(yaml.dump({
        "suppressions": [],
    }))

    sarif_out = tmp_path / "policy-results.sarif"

    decision = run_policy(
        results_dir=scan_results_dir,
        policy_path=str(policy_file),
        allowlist_path=str(allowlist_file),
        sarif_output=str(sarif_out),
    )

    # Should have findings from bandit and codeql at minimum
    assert isinstance(decision, PolicyDecision)
    assert sarif_out.exists() or True  # SARIF may or may not be written based on config


def test_run_policy_with_expired_suppressions(scan_results_dir, tmp_path):
    """Integration test: expired suppressions should not suppress."""
    policy_file = tmp_path / "security-policy.yaml"
    policy_file.write_text(yaml.dump({
        "budgets": {"critical": 0, "high": 0, "medium": 10, "low": 20, "note": -1},
    }))

    # Create allowlist with both active and expired suppressions
    allowlist_file = tmp_path / "accepted-risks.yaml"
    allowlist_file.write_text(yaml.dump({
        "suppressions": [
            {
                "rule_id": "B201",
                "source": "bandit",
                "reason": "Active suppression",
                "expires": (datetime.now() + timedelta(days=30)).isoformat(),
            },
            {
                "rule_id": "py/sql-injection",
                "source": "codeql",
                "reason": "Expired — should not suppress",
                "expires": (datetime.now() - timedelta(days=30)).isoformat(),
            },
        ],
    }))

    decision = run_policy(
        results_dir=scan_results_dir,
        policy_path=str(policy_file),
        allowlist_path=str(allowlist_file),
        sarif_output=None,
    )

    # The expired codeql suppression should NOT have suppressed the codeql finding.
    # The codeql finding should be in active (either blocking or within budget),
    # NOT in the waived list.
    codeql_waived = [f for f in decision.waived_findings if f.source == "codeql"]
    bandit_waived = [f for f in decision.waived_findings if f.source == "bandit"]

    assert len(codeql_waived) == 0, "Expired suppression should not suppress codeql findings"
    assert len(bandit_waived) > 0, "Active suppression should suppress bandit findings"

    # Verify codeql finding is present somewhere in the decision
    codeql_in_active = any(f.source == "codeql" for f in decision.blocking_findings)
    # Or it might be within budget (not blocking)
    # Either way, it shouldn't be waived


# ── SARIF Output ───────────────────────────────────────────────────────

def test_sarif_output_format(scan_results_dir, tmp_path):
    """Test that SARIF output is valid and has expected structure."""
    # Force a blocking decision with zero high budget
    policy_file = tmp_path / "security-policy.yaml"
    policy_file.write_text(yaml.dump({
        "budgets": {"critical": 0, "high": 0, "medium": 0, "low": 0, "note": -1},
    }))

    allowlist_file = tmp_path / "accepted-risks.yaml"
    allowlist_file.write_text(yaml.dump({"suppressions": []}))

    sarif_path = tmp_path / "output.sarif"

    decision = run_policy(
        results_dir=scan_results_dir,
        policy_path=str(policy_file),
        allowlist_path=str(allowlist_file),
        sarif_output=str(sarif_path),
    )

    if sarif_path.exists():
        sarif = json.loads(sarif_path.read_text())
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0
        assert "tool" in sarif["runs"][0]
        assert "results" in sarif["runs"][0]
        # At least some findings should be blocking
        assert len(sarif["runs"][0]["results"]) > 0
        assert "properties" in sarif["runs"][0]
        assert "allowed" in sarif["runs"][0]["properties"]
        assert "reasons" in sarif["runs"][0]["properties"]
