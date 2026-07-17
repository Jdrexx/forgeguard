
                                    ╔═══════════════════════════╗
                                    ║      F O R G E G U A R D  ║
                                    ║   DevSecOps Policy Engine  ║
                                    ╚═══════════════════════════╝

                          The pipeline is the product.

---

## Table of Contents

1. [What is ForgeGuard?](#what-is-forgeguard)
2. [Pipeline Architecture](#pipeline-architecture)
3. [The Differentiator: Custom Policy Engine](#the-differentiator)
4. [CWE Traceability Matrix](#cwe-traceability-matrix)
5. [Quick Start](#quick-start)
6. [Setup Guide](#setup-guide)
7. [Architecture Decisions](#architecture-decisions)
8. [Project Structure](#project-structure)

---

## What is ForgeGuard?

ForgeGuard is a **DevSecOps pipeline and policy engine** that treats security
as a build-time gate, not an afterthought. It is **not** "yet another Trivy
YAML" — it's a custom Python policy engine with:

- **Configurable severity budgets** (critical: 0, high: 0, medium: 5, low: 20)
- **Expiring suppressions** — waivers that expire on a date so they don't
  accumulate forever
- **Multi-scanner adapter pattern** — Bandit, pip-audit, CodeQL, Grype,
  ZAP, Gitleaks all feed into a single policy decision
- **SARIF output** for GitHub Security Tab integration
- **Fail-closed** — missing or corrupted scanner output blocks the release

Unlike most "DevSecOps" repos that are a single workflow file wrapping Trivy,
ForgeGuard's **policy gate is the product**. The vulnerable app is merely a
test fixture to demonstrate that the pipeline catches what it claims to catch.

---

## Pipeline Architecture

```
                        FORGEGUARD PIPELINE
                    ───────────────────────────

    ┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
    │  ╭─────╮  │    │  ╭─────╮  │    │  ╭─────╮     │    │  ╭─────╮     │
    │  │COMMIT│  │    │  │ SAST│  │    │  │BUILD│     │    │  │SIGN │     │
    │  │PUSH  │──┼──▶│  │     │──┼──▶│  │+    │─────┼──▶│  │+    │     │
    │  │PR    │  │    │  │CODEQ│  │    │  │SCAN │     │    │  │SBOM │     │
    │  ╰─────╯  │    │  │L    │  │    │  │+SBOM│     │    │  │     │     │
    │           │    │  ╰─────╯  │    │  ╰─────╯     │    │  ╰─────╯     │
    │  GitHub   │    │  pip-    │    │  Docker       │    │  cosign     │
    │  Actions  │    │  audit   │    │  Buildx       │    │  keyless    │
    │           │    │  Bandit  │    │  Grype        │    │  Syft SPDX  │
    │           │    │          │    │  Syft SBOM    │    │  CycloneDX  │
    └──────────┘    └──────────┘    └──────────────┘    └──────────────┘
        │                │                │                     │
        │                │                │                     │
        ▼                ▼                ▼                     ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    FORGEGUARD POLICY ENGINE                     │
    │                                                                 │
    │    ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌──────┐│
    │    │LOAD    │──▶│NORMALIZE│──▶│DEDUP   │──▶│ENRICH  │──▶│WAIVE ││
    │    │findings│   │        │   │        │   │        │   │      ││
    │    └────────┘   └────────┘   └────────┘   └────────┘   └──────┘│
    │                                                      │         │
    │                       ┌──────────┐                  │         │
    │                       │  DECIDE  │◀─────────────────┘         │
    │                       │ (budgets)│                            │
    │                       └──────────┘                            │
    │                            │                                  │
    │                            ▼                                  │
    │                       ┌──────────┐                            │
    │                       │  REPORT  │  ─── SARIF (GitHub Tab)    │
    │                       │          │  ─── ::error:: annotations │
    │                       │          │  ─── pass / fail exit code │
    │                       └──────────┘                            │
    └─────────────────────────────────────────────────────────────────┘
                        │
                        ▼
              POLICY DECISION: ALLOWED or BLOCKED


    Legend:
    ─────────────────────────────────────────────────────────────────────
    SAST   = Static Application Security Testing
    SBOM   = Software Bill of Materials (SPDX + CycloneDX)
    DAST   = Dynamic Application Security Testing (ZAP)
    SARIF  = Static Analysis Results Interchange Format

```

The pipeline runs as five sequential jobs in GitHub Actions:

| Job | Tools | Output |
|-----|-------|--------|
| **sast** | CodeQL (JavaScript, Python) | SARIF results |
| **deps-and-lint** | pip-audit, Bandit | JSON findings |
| **build-scan-sbom** | Docker Buildx, Grype, Syft, cosign | Image, Scan, SBOMs, Attestation |
| **dast** | OWASP ZAP baseline | ZAP JSON report |
| **policy-gate** | ForgeGuard Policy Engine | Pass/Fail + SARIF for GitHub |

---

## The Differentiator

Every bootcamp grad has a DevSecOps pipeline that wraps Trivy in a workflow
file. ForgeGuard is different because:

### 1. Custom Python Policy Engine (`security/policy.py`)

Not a YAML wrapper around a scanner — a real program that:

- **Loads findings** from multiple scanners via an adapter pattern
- **Normalizes** severities into a canonical enum
- **Deduplicates** by fingerprint, keeping the highest severity
- **Enriches** with context (e.g., marks SQLi as fixable)
- **Waives** based on expiring suppressions from YAML allowlist
- **Decides** by checking severity budgets
- **Reports** with SARIF output and GitHub Actions annotations

### 2. Expiring Suppressions

Most security tools let you suppress findings forever. That's how
"temporary" waivers become permanent technical debt.

```yaml
suppressions:
  - rule_id: "B201"
    reason: "Known test fixture"
    expires: "2027-12-31"   # This one is active

  - rule_id: "CWE-200"
    reason: "Was going to fix (EXPIRED)"
    expires: "2024-01-15"   # This one is ignored — past date
```

Expired suppressions **stop suppressing**. The finding counts against the
budget. The CI fails. This forces teams to regularly review and re-authorize
waivers.

### 3. Fail-Closed

If a scanner produces no output because the tool crashed, the output format
changed, or the file is missing, the policy engine **fails the pipeline**.
Missing scanner output is treated as a finding, not a pass.

### 4. Multi-Scanner Adapter Pattern

Each scanner has an adapter class that knows how to parse its output format:

```
security/adapters/
├── __init__.py    ← BanditAdapter, PipAuditAdapter, CodeQLAdapter,
│                    GrypeAdapter, ZAPAdapter, GitleaksAdapter
```

Add a new scanner: create a `BaseAdapter` subclass, register it in
`ALL_ADAPTERS`, done.

### 5. SARIF Output

The policy engine outputs a **SARIF v2.1.0** log file that the
`github/codeql-action/upload-sarif` action uploads to the GitHub Security
tab. This means ForgeGuard findings appear alongside CodeQL findings in the
same dashboard.

---

## CWE Traceability Matrix

Each vulnerable endpoint in this repo maps to a CWE, a fix, and a tool that
detects it. This table proves the pipeline catches what it claims to catch.

| CWE | Vulnerability | Vulnerable File | Fixed File | What the Fix Does | Tool That Catches It |
|-----|---------------|----------------|------------|-------------------|---------------------|
| **CWE-89** | SQL Injection | [`app/vulnerable/sqli.py`](app/vulnerable/sqli.py) | [`app/fixed/sqli.py`](app/fixed/sqli.py) | Parameterized queries instead of string interpolation | Bandit (B201), CodeQL (py/sql-injection) |
| **CWE-79** | Cross-Site Scripting | [`app/vulnerable/xss.py`](app/vulnerable/xss.py) | [`app/fixed/xss.py`](app/fixed/xss.py) | HTML-escaped output via `html.escape()` | Bandit (B303), CodeQL (py/xss) |
| **CWE-22** | Path Traversal | [`app/vulnerable/traversal.py`](app/vulnerable/traversal.py) | [`app/fixed/traversal.py`](app/fixed/traversal.py) | Path containment check (`requested.startswith(BASE_DIR)`) | Bandit (B301), CodeQL (py/path-injection) |
| **CWE-200** | Information Exposure | [`app/vulnerable/info_leak.py`](app/vulnerable/info_leak.py) | [`app/fixed/info_leak.py`](app/fixed/info_leak.py) | Debug endpoints removed entirely | Bandit (B108), CodeQL (py/clear-text-storage-sensitive-data) |
| **CWE-352** | CSRF | [`app/vulnerable/csrf.py`](app/vulnerable/csrf.py) | [`app/fixed/csrf.py`](app/fixed/csrf.py) | CSRF token validation via dependency injection | ZAP (10010, 10020) |
| **CWE-502** | Unsafe Deserialization | [`app/vulnerable/pickle_rce.py`](app/vulnerable/pickle_rce.py) | [`app/fixed/pickle_rce.py`](app/fixed/pickle_rce.py) | Replaced `pickle.loads()` with `json.loads()` | Bandit (B403), CodeQL (py/unsafe-deserialization) |

---

## Quick Start

### Prerequisites

- Python 3.12+
- Docker & Docker Compose (for local demo)
- A GitHub account (for Actions + Security tab)

### 1. Clone and Install

```bash
git clone https://github.com/jdrexx/forgeguard.git
cd forgeguard
pip install -r requirements.txt
```

### 2. Run the Policy Engine Locally

```bash
# Generate mock scanner fixtures
python scripts/generate_fixtures.py scan-fixtures/

# Run the policy gate
python -m security.policy scan-fixtures/ \
    --policy policy/security-policy.yaml \
    --allowlist policy/accepted-risks.yaml \
    --sarif-output policy-results.sarif
```

### 3. Run the Demo App

```bash
# Start in production mode (no vulnerable endpoints)
docker compose up -d app

# Or in demo mode (vulnerable endpoints available under /vuln/*)
DEMO_MODE=1 docker compose up -d app

# Check health
curl http://localhost:8000/livez    # {"status": "alive"}
curl http://localhost:8000/readyz   # {"status": "ready", "demo_mode": false}
```

### 4. Run Tests

```bash
pip install -r test-requirements.txt
python -m pytest tests/ -v --cov=security
```

---

## Setup Guide

### GitHub Actions

1. Push this repo to GitHub
2. Enable GitHub Actions in your repository settings
3. The `security-gate.yml` workflow runs automatically on push/PR to main
4. Configure these repository secrets:

| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | Auto-provided — no setup needed |
| (none required) | Everything else uses OIDC / keyless |

### GitHub Security Tab

ForgeGuard SARIF output appears in the GitHub Security tab automatically
because the workflow uploads it via `codeql-action/upload-sarif`.

### Docker

```bash
# Build
docker build -t forgeguard .

# Run with digest-pinned base
docker run --rm -p 8000:8000 forgeguard

# Full pipeline with compose
docker compose -f docker-compose.yml up -d
```

### Container Signing

Container images are signed with **cosign keyless** signing using GitHub
OIDC. No key management needed:

```bash
cosign verify \
    --certificate-identity "$GITHUB_ACTOR@users.noreply.github.com" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/jdrexx/forgeguard:latest
```

---

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Policy engine language | Python | Most security engineers are Python-literate; rich ecosystem for JSON/SARIF/YAML parsing |
| Adapter pattern | Separate adapter classes | Adding a new scanner = one new file, no changes to core logic |
| Expiring suppressions | ISO 8601 dates in YAML | Human-readable, git-trackable, CI-enforceable |
| Fail-closed | Missing scanner output blocks release | Better to fail a build than ship a vulnerability |
| SARIF upload | via codeql-action | Reuses existing GitHub Security Tab infrastructure |
| SBOM format | SPDX + CycloneDX | Both are industry standards; SPDX for cosign attestation, CycloneDX for dependency tools |
| Buildx --load | Multi-stage with --load | Ensures the image is available for Grype scanning in the same job |
| Distroless runtime | python:3.12-slim-bookworm | Minimal attack surface; no shell, no package manager in runtime |
| cosign keyless | GitHub OIDC | No key management, no rotating secrets, no key ceremony |
| Workflow pinning | Commit SHAs | Supply-chain security; prevents action tag mutations |

---

## Project Structure

```
forgeguard/
├── .github/
│   └── workflows/
│       ├── security-gate.yml       # Main pipeline (SAST → Build → Scan → Sign → Policy)
│       └── release.yml             # Release pipeline (signed image + SBOM publish)
│
├── security/                        # ← POLICY ENGINE: the product
│   ├── __init__.py
│   ├── models.py                   # Finding, PolicyDecision, Suppression dataclasses
│   ├── policy.py                   # Core policy gate (load → normalize → dedup → enrich → waive → decide → report)
│   └── adapters/
│       └── __init__.py             # Bandit, pip-audit, CodeQL, Grype, ZAP, Gitleaks adapters
│
├── app/                            # Test fixture (not the product)
│   ├── __init__.py
│   ├── main.py                     # FastAPI with DEMO_MODE toggle
│   ├── vulnerable/                 # Deliberately vulnerable endpoints
│   │   ├── sqli.py                 # CWE-89
│   │   ├── xss.py                  # CWE-79
│   │   ├── traversal.py            # CWE-22
│   │   ├── info_leak.py            # CWE-200
│   │   ├── csrf.py                 # CWE-352
│   │   └── pickle_rce.py           # CWE-502
│   └── fixed/                      # Remediated versions
│       ├── sqli.py                 # Parameterized queries
│       ├── xss.py                  # Output encoding
│       ├── traversal.py            # Path containment
│       ├── info_leak.py            # Stripped debug endpoints
│       ├── csrf.py                 # CSRF middleware
│       └── pickle_rce.py           # JSON instead of pickle
│
├── policy/                         # Security policy configuration
│   ├── security-policy.yaml        # Severity budgets
│   ├── accepted-risks.yaml         # Expiring suppressions
│   └── bandit.yaml                 # Bandit configuration
│
├── scripts/
│   └── generate_fixtures.py        # Generate mock scanner output for testing
│
├── tests/                          # Tests
│   ├── test_policy.py              # Policy gate unit tests
│   ├── test_adapters.py            # Scanner adapter tests
│   └── test_app.py                 # App fixture tests
│
├── infra/                          # Infrastructure as Code
│   ├── main.tf                     # Terraform for AWS ECS Fargate
│   └── bake.hcl                    # Docker Buildx bake configuration
│
├── Dockerfile                      # Multi-stage build, distroless runtime
├── docker-compose.yml              # Local demo (app + ZAP + Redis)
├── railway.json                    # Railway deployment config
├── requirements.txt                # Python dependencies
├── test-requirements.txt           # Test dependencies
├── ENVIRONMENT.md                  # Environment variable reference
├── SECURITY.md                     # Vulnerability reporting policy
└── KNOWN_LIMITATIONS.md            # Known limitations
```

---

## License

MIT — see [LICENSE](LICENSE) (not included — add your own).

---

*ForgeGuard was built as a portfolio differentiator. The pipeline is the product.
The app is just a test fixture. Every bootcamp grad has a Trivy workflow.
Not every bootcamp grad has a custom policy engine with expiring suppressions
and SARIF output.*
