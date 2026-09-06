"""
ForgeGuard — Scanner Adapters.

Each adapter knows how to parse its scanner's output format into Finding objects.
Add a new scanner by subclassing BaseAdapter and registering it in ALL_ADAPTERS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Finding


@dataclass
class ParseResult:
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


class BaseAdapter:
    """Base class for scanner output adapters."""

    name: str = "base"

    def find_output(self, directory: Path) -> Path | None:
        """Find the scanner output file in the results directory."""
        raise NotImplementedError

    def parse(self, directory: str | Path) -> ParseResult:
        """Parse scanner output and return findings."""
        directory = Path(directory)
        output_path = self.find_output(directory)
        if output_path is None:
            return ParseResult(error=f"No {self.name} output found in {directory}")
        try:
            raw = output_path.read_text()
            return self._parse_content(raw, output_path)
        except (IOError, json.JSONDecodeError, yaml.YAMLError) as exc:
            return ParseResult(error=str(exc))

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        raise NotImplementedError


import json
import yaml

# ── Bandit Adapter ──────────────────────────────────────────────────────


class BanditAdapter(BaseAdapter):
    name = "bandit"

    def find_output(self, directory: Path) -> Path | None:
        for candidate in ["bandit.json", "bandit-output.json"]:
            p = directory / candidate
            if p.exists():
                return p
        return None

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        data = json.loads(content)
        findings = []
        for result in data.get("results", []):
            f = Finding(
                source="bandit",
                rule_id=result.get("test_id", "B000"),
                severity=_map_bandit_severity(result.get("issue_severity", "low")),
                cwes=_bandit_cwe(result.get("test_id", "")),
                file=result.get("filename", ""),
                line=result.get("line_number", 0) or 0,
                column=result.get("col_offset", 0) or 0,
                description=result.get("issue_text", ""),
                fix_available=result.get("confidence", "HIGH") == "HIGH",
                raw=result,
            )
            findings.append(f)
        return ParseResult(findings=findings)


def _map_bandit_severity(s: str) -> str:
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(s.upper(), "low")


def _bandit_cwe(test_id: str) -> list[str]:
    mapping = {
        "B001": ["CWE-200"],
        "B105": ["CWE-522"],
        "B106": ["CWE-200"],
        "B107": ["CWE-200"],
        "B108": ["CWE-200"],
        "B110": ["CWE-200"],
        "B201": ["CWE-89"],
        "B202": ["CWE-89"],
        "B301": ["CWE-22"],
        "B302": ["CWE-22"],
        "B303": ["CWE-79"],
        "B401": ["CWE-94"],
        "B402": ["CWE-94"],
        "B403": ["CWE-502"],
        "B501": ["CWE-330"],
        "B502": ["CWE-330"],
        "B601": ["CWE-78"],
        "B602": ["CWE-78"],
        "B603": ["CWE-78"],
        "B605": ["CWE-78"],
        "B607": ["CWE-78"],
        "B701": ["CWE-326"],
    }
    return mapping.get(test_id, [])


# ── pip-audit Adapter ──────────────────────────────────────────────────


class PipAuditAdapter(BaseAdapter):
    name = "pip-audit"

    def find_output(self, directory: Path) -> Path | None:
        for candidate in ["pip-audit.json", "pip-audit-output.json"]:
            p = directory / candidate
            if p.exists():
                return p
        return None

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        data = json.loads(content)
        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                f = Finding(
                    source="pip-audit",
                    rule_id=vuln.get("id", "UNKNOWN"),
                    severity=_map_pip_severity(vuln.get("severity", "medium")),
                    cwes=[
                        cwe["id"]
                        for cwe in vuln.get("aliases", [])
                        if cwe.get("id", "").startswith("CWE-")
                    ],
                    file=dep.get("name", ""),
                    line=0,
                    description=f"{vuln.get('id', '')}: {vuln.get('description', '')}",
                    fix_available=True,
                    raw=vuln,
                )
                findings.append(f)
        return ParseResult(findings=findings)


def _map_pip_severity(s: str | float | int) -> str:
    if isinstance(s, (int, float)):
        if s >= 9.0:
            return "critical"
        if s >= 7.0:
            return "high"
        if s >= 4.0:
            return "medium"
        return "low"
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get(s.upper(), "medium")


# ── CodeQL Adapter ─────────────────────────────────────────────────────


class CodeQLAdapter(BaseAdapter):
    name = "codeql"

    def find_output(self, directory: Path) -> Path | None:
        for candidate in ["codeql.sarif", "codeql-results.sarif"]:
            p = directory / candidate
            if p.exists():
                return p
        return None

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        data = json.loads(content)
        findings = []
        for run in data.get("runs", []):
            tool_name = (run.get("tool", {}).get("driver", {})).get("name", "codeql")
            for result in run.get("results", []):
                loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
                region = loc.get("region", {})
                f = Finding(
                    source="codeql",
                    rule_id=result.get("ruleId", "unknown"),
                    severity=_map_codeql_level(result.get("level", "warning")),
                    cwes=_extract_codeql_cwes(result),
                    file=loc.get("artifactLocation", {}).get("uri", ""),
                    line=region.get("startLine", 0) or 0,
                    column=region.get("startColumn", 0) or 0,
                    description=result.get("message", {}).get("text", ""),
                    fix_available=False,
                    raw=result,
                )
                findings.append(f)
        return ParseResult(findings=findings)


def _map_codeql_level(level: str) -> str:
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")


def _extract_codeql_cwes(result: dict) -> list[str]:
    """Extract CWE references from CodeQL SARIF result properties."""
    props = result.get("properties", {}) or {}
    tags = props.get("tags", [])
    return [t for t in tags if t.startswith("CWE-")]


# ── Grype Adapter ──────────────────────────────────────────────────────


class GrypeAdapter(BaseAdapter):
    name = "grype"

    def find_output(self, directory: Path) -> Path | None:
        for candidate in ["grype.json", "grype-output.json", "vuln-scan.json"]:
            p = directory / candidate
            if p.exists():
                return p
        return None

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        data = json.loads(content)
        findings = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            # build CWE list from related URLs / namespace
            cwes = []
            namespace = vuln.get("namespace", "")
            if "CWE" in namespace:
                cwes.append(namespace)

            f = Finding(
                source="grype",
                rule_id=vuln.get("id", "UNKNOWN"),
                severity=_map_grype_severity(vuln.get("severity", "Medium")),
                cwes=cwes,
                file=f"{artifact.get('name', '')}@{artifact.get('version', '')}",
                line=0,
                description=f"{vuln.get('id', '')}: {vuln.get('description', '')[:200]}",
                fix_available=bool(vuln.get("fix", {}).get("versions", [])),
                raw=match,
            )
            findings.append(f)
        return ParseResult(findings=findings)


def _map_grype_severity(s: str) -> str:
    m = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Negligible": "note",
    }
    return m.get(s, s.lower())


# ── ZAP Adapter ────────────────────────────────────────────────────────


class ZAPAdapter(BaseAdapter):
    name = "zap"

    def find_output(self, directory: Path) -> Path | None:
        for candidate in ["zap.json", "zap-output.json", "zap-report.json"]:
            p = directory / candidate
            if p.exists():
                return p
        return None

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        data = json.loads(content)
        findings = []

        # ZAP JSON formats vary: site-level or top-level alerts
        sites = data.get("site", [data])

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                risk = alert.get("riskdesc", "").lower()
                instances = alert.get("instances", [{}])
                for inst in instances:
                    uri = inst.get("uri", "")
                    method = inst.get("method", "")
                    f = Finding(
                        source="zap",
                        rule_id=alert.get("id", "0"),
                        severity=_map_zap_risk(alert.get("risk", "Low")),
                        cwes=_zap_cwe(alert.get("cweid", 0)),
                        file=uri,
                        line=0,
                        description=f"{alert.get('name', '')} [{alert.get('alert', '')}]",
                        fix_available=False,
                        raw=alert,
                    )
                    findings.append(f)
        return ParseResult(findings=findings)


def _map_zap_risk(risk: str | int) -> str:
    m = {
        3: "high",
        2: "medium",
        1: "low",
        0: "note",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "note",
    }
    return m.get(risk, "medium")


def _zap_cwe(cweid: int) -> list[str]:
    if cweid == 0:
        return []
    return [f"CWE-{cweid}"]


# ── Gitleaks Adapter ───────────────────────────────────────────────────


class GitleaksAdapter(BaseAdapter):
    name = "gitleaks"

    def find_output(self, directory: Path) -> Path | None:
        for candidate in ["gitleaks.json", "gitleaks-output.json"]:
            p = directory / candidate
            if p.exists():
                return p
        return None

    def _parse_content(self, content: str, path: Path) -> ParseResult:
        data = json.loads(content)
        findings = []
        # gitleaks can output an array of findings or a JSON object with findings key
        entries = data if isinstance(data, list) else data.get("findings", [])

        for entry in entries:
            cwe = entry.get("CWE", "")
            f = Finding(
                source="gitleaks",
                rule_id=entry.get("RuleID", entry.get("rule", "unknown")),
                severity=_map_gitleaks_severity(entry.get("Severity", "medium")),
                cwes=[cwe] if cwe and cwe.startswith("CWE-") else ["CWE-798"],
                file=entry.get("File", entry.get("file", "")),
                line=entry.get("StartLine", entry.get("startLine", 0)) or 0,
                column=entry.get("StartColumn", entry.get("startColumn", 0)) or 0,
                description=f"Secret leak: {entry.get('Description', entry.get('description', ''))}",
                fix_available=False,
                raw=entry,
            )
            findings.append(f)
        return ParseResult(findings=findings)


def _map_gitleaks_severity(s: str) -> str:
    return s.lower() if s.lower() in ("critical", "high", "medium", "low") else "high"


# ── Registry ───────────────────────────────────────────────────────────

ALL_ADAPTERS = [
    BanditAdapter(),
    PipAuditAdapter(),
    CodeQLAdapter(),
    GrypeAdapter(),
    ZAPAdapter(),
    GitleaksAdapter(),
]