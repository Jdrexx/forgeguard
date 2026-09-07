#!/usr/bin/env python3
"""
ForgeGuard — Policy Gate.

The core differentiator: a custom policy engine that loads scanner findings,
applies severity budgets, evaluates expiring suppressions, and decides whether
the pipeline passes or fails.

Usage:
    python -m security.policy scan-results/ \
        --policy policy/security-policy.yaml \
        --allowlist policy/accepted-risks.yaml \
        --sarif-output results.sarif
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import yaml
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import ALL_ADAPTERS
from .models import Finding, PolicyDecision, Severity, Suppression


# ── default budgets ────────────────────────────────────────────────────
DEFAULT_BUDGETS: dict[str, int] = {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 20,
    "note": -1,  # -1 means unlimited
}


@dataclass
class PolicyConfig:
    """Policy configuration loaded from YAML."""

    budgets: dict[str, int] = None
    fail_on_missing_tool: bool = True
    require_reachable_proven: bool = False
    sarif_output: bool = True

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyConfig":
        raw = yaml.safe_load(Path(path).read_text()) or {}
        cfg = cls()
        cfg.budgets = raw.get("budgets", dict(DEFAULT_BUDGETS))
        cfg.fail_on_missing_tool = raw.get("fail_on_missing_tool", True)
        cfg.require_reachable_proven = raw.get("require_reachable_proven", False)
        # merge in any explicit overrides from defaults
        for sev in DEFAULT_BUDGETS:
            cfg.budgets.setdefault(sev, DEFAULT_BUDGETS[sev])
        return cfg


# ── pipeline stages ────────────────────────────────────────────────────


def load_results(
    results_dir: str | Path, adapters: list | None = None
) -> list[Finding]:
    """
    Load scanner output files from a directory.
    Uses the adapter pattern: each adapter knows how to parse its tool's output.
    Fail-closed: missing or corrupted scanner output raises.
    """
    results_dir = Path(results_dir)
    if not results_dir.is_dir():
        raise RuntimeError(f"Results directory not found: {results_dir}")

    adapters = adapters or ALL_ADAPTERS
    findings: list[Finding] = []

    for adapter in adapters:
        outcome = adapter.parse(results_dir)
        if outcome.error:
            raise RuntimeError(
                f"[{adapter.name}] Failed to parse scanner output: {outcome.error}"
            )
        findings.extend(outcome.findings)

    return findings


def normalize(findings: list[Finding]) -> list[Finding]:
    """Normalize severity names, strip whitespace, ensure enums.

    Scanner output is untrusted: any severity label outside the enum
    (e.g. grype's "Unknown") degrades to NOTE instead of crashing the gate.
    """
    for f in findings:
        if isinstance(f.severity, str):
            try:
                f.severity = Severity(f.severity.lower().strip())
            except ValueError:
                f.severity = Severity.NOTE
        if f.file:
            f.file = f.file.strip()
    return findings


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate by fingerprint, keeping the highest severity.
    If two findings have the same fingerprint, keep the one with the
    highest severity (closest to critical).
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        existing = seen.get(f.fingerprint)
        if existing is None:
            seen[f.fingerprint] = f
        elif f.severity > existing.severity:
            seen[f.fingerprint] = f
        elif f.severity == existing.severity and f.reachable and not existing.reachable:
            seen[f.fingerprint] = f
    return list(seen.values())


def enrich(findings: list[Finding]) -> list[Finding]:
    """
    Enrich findings with additional context.
    For now: mark CWE-89/SQLi findings as fix_available since parameterized
    queries are a well-known remediation.
    """
    cwe_to_fix = {"CWE-89": True, "CWE-79": True, "CWE-22": True}
    for f in findings:
        for cwe in f.cwes:
            if cwe in cwe_to_fix:
                f.fix_available = True
    return findings


def waive(
    findings: list[Finding], suppressions: list[Suppression]
) -> tuple[list[Finding], list[Finding]]:
    """
    Apply suppressions. Returns (active_findings, waived_findings).
    Expired suppressions are silently ignored.
    """
    active: list[Finding] = []
    waived: list[Finding] = []

    for f in findings:
        suppressed = False
        for sup in suppressions:
            if sup.matches(f):
                suppressed = True
                break
        if suppressed:
            waived.append(f)
        else:
            active.append(f)

    return active, waived


def decide(
    findings: list[Finding],
    budgets: dict[str, int],
) -> PolicyDecision:
    """
    Decide whether the pipeline passes based on severity budgets.
    Returns a PolicyDecision with details.
    """
    decision = PolicyDecision()
    decision.scores = {sev: 0 for sev in DEFAULT_BUDGETS}

    for f in findings:
        sev = f.severity.value
        budget = budgets.get(sev, -1)
        if budget == -1:
            continue  # unbounded
        decision.scores[sev] += 1
        if decision.scores[sev] > budget:
            decision.blocking_findings.append(f)

    if decision.blocking_findings:
        decision.allowed = False
        decision.reasons.append(
            f"Severity budget breached: "
            f"{ {s: decision.scores[s] for s in budgets if budgets.get(s, -1) >= 0} }"
        )

    return decision


def report(decision: PolicyDecision, sarif_path: str | None = None):
    """
    Report policy decision.
    - Prints to stdout
    - Generates GitHub Actions annotations
    - Optionally writes SARIF output
    """
    # summary
    total_blocking = len(decision.blocking_findings)
    total_waived = len(decision.waived_findings)
    print(f"\n═══════════════════════════════════════", file=sys.stderr)
    print(f"  ForgeGuard Policy Decision", file=sys.stderr)
    print(f"  ALLOWED: {decision.allowed}", file=sys.stderr)
    print(f"  Blocking: {total_blocking}  |  Waived: {total_waived}", file=sys.stderr)
    if decision.scores:
        for sev, count in decision.scores.items():
            if count > 0:
                print(f"    {sev}: {count}", file=sys.stderr)
    for reason in decision.reasons:
        print(f"  reason: {reason}", file=sys.stderr)
    print(f"═══════════════════════════════════════\n", file=sys.stderr)

    # GitHub Actions annotations
    gh_annotations = os.environ.get("GITHUB_ACTIONS") == "true"
    for f in decision.blocking_findings:
        file_str = f.file or "unknown"
        line_str = f.line or 1
        msg = f"[{f.severity.value}] {f.source}/{f.rule_id}: {f.description}"
        if gh_annotations:
            print(f"::error file={file_str},line={line_str},title={f.source}::{msg}")
        else:
            print(f"  ERROR  {file_str}:{line_str}  {msg}", file=sys.stderr)

    # SARIF output
    if sarif_path:
        _write_sarif(decision, sarif_path)


def _write_sarif(decision: PolicyDecision, path: str):
    """Write a SARIF v2.1.0 log file for GitHub Security tab integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ForgeGuard",
                        "informationUri": "https://github.com/jdrexx/forgeguard",
                    }
                },
                "results": [f.to_sarif() for f in decision.blocking_findings],
                "properties": {
                    "allowed": decision.allowed,
                    "reasons": decision.reasons,
                    "scores": decision.scores,
                },
            }
        ],
    }
    Path(path).write_text(json.dumps(sarif, indent=2))
    print(f"  → SARIF output written to {path}", file=sys.stderr)


# ── main entry point ───────────────────────────────────────────────────


def run_policy(
    results_dir: str | Path,
    policy_path: str | Path = "policy/security-policy.yaml",
    allowlist_path: str | Path = "policy/accepted-risks.yaml",
    sarif_output: str | None = "policy-results.sarif",
) -> PolicyDecision:
    """
    End-to-end policy evaluation.
    Pipeline: load → normalize → deduplicate → enrich → waive → decide → report
    """
    config = PolicyConfig.from_file(policy_path)

    # 1. load
    print(f"→ Loading findings from {results_dir} ...", file=sys.stderr)
    findings = load_results(results_dir)

    # 2. normalize
    findings = normalize(findings)

    # 3. deduplicate
    before = len(findings)
    findings = deduplicate(findings)
    duped = before - len(findings)
    if duped:
        print(f"  dedup: removed {duped} duplicates", file=sys.stderr)

    # 4. enrich
    findings = enrich(findings)

    # 5. waive
    suppressions = _load_suppressions(allowlist_path)
    active, waived = waive(findings, suppressions)
    if waived:
        print(f"  waived: {len(waived)} findings suppressed", file=sys.stderr)

    # 6. decide
    decision = decide(active, config.budgets)
    decision.waived_findings = waived

    # 7. report
    report(decision, sarif_path=sarif_output if config.sarif_output else None)

    return decision


def _load_suppressions(path: str | Path) -> list[Suppression]:
    """Load suppressions from YAML allowlist, dropping expired ones."""
    path = Path(path)
    if not path.exists():
        print(
            f"  (no allowlist at {path}, continuing without suppressions)",
            file=sys.stderr,
        )
        return []

    raw = yaml.safe_load(path.read_text()) or {}
    suppressions: list[Suppression] = []
    dropped = 0

    for entry in raw.get("suppressions", []):
        sup = Suppression(
            rule_id=entry.get("rule_id", ""),
            file=entry.get("file", ""),
            reason=entry.get("reason", ""),
            source=entry.get("source", ""),
            expires=None,
        )
        if entry.get("expires"):
            try:
                sup.expires = datetime.fromisoformat(entry["expires"])
            except ValueError:
                print(f"  ⚠ invalid expiry date: {entry['expires']}", file=sys.stderr)
        if sup.is_expired:
            dropped += 1
            print(
                f"  ✗ skipping expired suppression: rule={sup.rule_id} (expired {sup.expires})",
                file=sys.stderr,
            )
        else:
            suppressions.append(sup)

    if dropped:
        print(f"  dropped {dropped} expired suppression(s)", file=sys.stderr)
    return suppressions


def cli():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="ForgeGuard — policy gate for DevSecOps pipelines",
    )
    parser.add_argument("results_dir", help="Directory containing scanner output files")
    parser.add_argument(
        "--policy",
        default="policy/security-policy.yaml",
        help="Path to security policy YAML",
    )
    parser.add_argument(
        "--allowlist",
        default="policy/accepted-risks.yaml",
        help="Path to accepted risks / suppressions YAML",
    )
    parser.add_argument(
        "--sarif-output",
        default=None,
        help="Path for SARIF output (default: policy-results.sarif)",
    )
    parser.add_argument(
        "--no-sarif",
        action="store_true",
        help="Disable SARIF output",
    )
    args = parser.parse_args()

    sarif_out = args.sarif_output
    if args.no_sarif:
        sarif_out = None

    decision = run_policy(
        results_dir=args.results_dir,
        policy_path=args.policy,
        allowlist_path=args.allowlist,
        sarif_output=sarif_out,
    )

    sys.exit(0 if decision.allowed else 1)


if __name__ == "__main__":
    cli()