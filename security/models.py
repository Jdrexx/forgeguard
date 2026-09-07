"""
ForgeGuard — core domain models.

Finding and PolicyDecision dataclasses used throughout the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOTE = "note"

    def __ge__(self, other: Severity) -> bool:
        rank = {s: i for i, s in enumerate(Severity)}
        return rank[self] <= rank[other]

    def __gt__(self, other: Severity) -> bool:
        rank = {s: i for i, s in enumerate(Severity)}
        return rank[self] < rank[other]


SEVERITY_ORDER = [s.value for s in Severity]
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "note": 0}


@dataclass
class Finding:
    """A normalized security finding from any scanner."""

    fingerprint: str = ""
    source: str = ""  # which scanner: bandit, pip-audit, codeql, grype, zap, gitleaks
    rule_id: str = ""
    severity: Severity = Severity.NOTE
    cwes: list[str] = field(default_factory=list)
    file: str = ""
    line: int = 0
    column: int = 0
    fix_available: bool = False
    reachable: bool = True  # True unless proved otherwise
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.fingerprint:
            raw = json.dumps(self.raw, sort_keys=True) if self.raw else ""
            sig = f"{self.source}:{self.rule_id}:{self.file}:{self.line}:{raw}"
            self.fingerprint = hashlib.sha256(sig.encode()).hexdigest()[:16]

    @property
    def weighted_severity(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity.value, 0)

    def to_sarif(self) -> dict:
        """Render this finding as a SARIF result object."""
        # GitHub's SARIF processor requires artifact URIs to be valid,
        # file-relative paths: package-name findings (grype: 'zlib1g@1:1.2.13')
        # contain colons and remote URLs (pip-audit advisories) use http://,
        # both of which are rejected. Fall back to a synthetic safe path.
        uri = self.file or ""
        if not uri or "://" in uri or ":" in uri:
            safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", self.rule_id or "finding")
            uri = f"{self.source}/{safe_id}.txt"
        location: dict = {"artifactLocation": {"uri": uri}}
        # GitHub's SARIF validator rejects startLine < 1; findings without a
        # source line (e.g. grype OS-package matches) get no region at all.
        if self.line and self.line > 0:
            location["region"] = {
                "startLine": self.line,
                "startColumn": max(self.column, 1),
            }
        return {
            "ruleId": self.rule_id,
            "ruleIndex": 0,
            "level": "error"
            if self.severity in (Severity.CRITICAL, Severity.HIGH)
            else "warning",
            "message": {"text": self.description or f"{self.source}: {self.rule_id}"},
            "locations": [{"physicalLocation": location}],
            "properties": {
                "severity": self.severity.value,
                "source": self.source,
                "cwes": self.cwes,
                "fixAvailable": self.fix_available,
                "reachable": self.reachable,
                "fingerprint": self.fingerprint,
            },
        }


@dataclass
class Suppression:
    """A single waiver entry from the accepted-risks YAML."""

    rule_id: str = ""
    file: str = ""
    reason: str = ""
    expires: datetime | None = None
    source: str = ""  # which scanner this applies to (empty = all)

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return datetime.now() >= self.expires

    def matches(self, finding: Finding) -> bool:
        if self.is_expired:
            return False
        if self.source and self.source != finding.source:
            return False
        if self.rule_id and self.rule_id != finding.rule_id:
            return False
        if self.file and self.file != finding.file:
            return False
        return True


@dataclass
class PolicyDecision:
    """Result of evaluating findings against policy."""

    allowed: bool = True
    blocking_findings: list[Finding] = field(default_factory=list)
    waived_findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)