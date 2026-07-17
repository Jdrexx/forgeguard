# Known Limitations

These are documented trade-offs and areas for future improvement.

## Policy Engine

1. **Single-threaded evaluation** — Findings are processed sequentially.
   For large result sets (>100K findings), this could be slow. Future work
   could batch-process in chunks or use `multiprocessing`.

2. **No caching** — Every policy evaluation runs from scratch. If the same
   scanner output is evaluated multiple times (e.g., in development), there's
   no memoization. This is intentional for CI but suboptimal for local dev.

3. **Severity mapping is heuristic** — The adapter's severity mapping from
   each scanner's native scale to ForgeGuard's canonical scale is approximate.
   Grype's "Medium" may not map perfectly to Bandit's "MEDIUM". We've erred
   on the side of over-classifying.

4. **CWE extraction is fragile** — Each adapter extracts CWEs differently:
   - Bandit: hardcoded mapping table (brittle when rules change)
   - CodeQL: reads tags from SARIF properties
   - Grype: tries namespace-based extraction
   - ZAP: constructs from cweid integer
   - Gitleaks: reads CWE field directly

   A unified CWE taxonomy across all scanners would be better.

## Sample App

1. **Not production code** — The FastAPI app is a **test fixture**, not a
   production application. It intentionally contains vulnerabilities for
   pipeline demonstration purposes. Do not deploy it as-is.

2. **SQLite in memory** — Both vulnerable and fixed SQLi endpoints use
   `:memory:` SQLite databases. This works for demo but is not representative
   of real database usage patterns.

3. **No authentication** — The app has no auth middleware. This is deliberate
   (simplifies the demo) but means the ZAP scan catches only a subset of
   real-world DAST issues.

## Workflows

1. **CodeQL matrix** — The CodeQL job runs JavaScript and Python in parallel.
   For repos without JavaScript code, the JS job wastes runner minutes. Add
   a path filter or remove the JavaScript matrix entry.

2. **Grype fail-build: false** — The Grype scan is configured `fail-build: false`
   because the ForgeGuard policy gate makes the final pass/fail decision. This
   means a critical CVE in the base image will not fail the build until the
   policy gate runs. In an emergency, you may want Grype to fail early.

3. **ZAP baseline only** — The workflow runs a ZAP baseline scan (spider +
   passive scan). It does not run an active scan, which would find more
   vulnerabilities but take much longer and potentially damage the target.

4. **Workflow pinning is manual** — Action SHAs are pinned at authoring time.
   They need periodic updates. Use Dependabot or Renovate for automated updates.

## Infrastructure

1. **Terraform: single-region** — The Terraform config deploys to a single
   AWS region. Multi-region failover is not implemented.

2. **No WAF** — There's no AWS WAF attached to the ALB. In production, you'd
   want WAF rate limiting and IP filtering.

3. **No secrets manager** — The ECS task definition uses environment variables
   for configuration. In production, use AWS Secrets Manager or Parameter Store.

## Testing

1. **Fixture-based** — The tests use generated fixture data, not real scanner
   output. This means the adapters are tested against known formats, but format
   changes in scanner tools could break parsing silently.

2. **No integration tests** — The test suite doesn't spin up Docker containers
   or run real scanners. This is a gap that should be filled for CI reliability.

3. **Coverage gaps** — The test suite covers the policy engine logic well,
   but the adapter edge cases (malformed input, missing fields, unexpected
   JSON structure) are not fully tested.

## Future Work

- [ ] Multi-threaded finding processing for large result sets
- [ ] CVE-to-CWE mapping using NVD API enrichment
- [ ] Active DAST scan mode (ZAP full scan)
- [ ] Kubernetes admission controller integration
- [ ] Webhook-based policy evaluation (not just CI-gated)
- [ ] Drift detection: alert when accepted risks keep getting re-authorized
- [ ] Dependency graph: track which findings were waived by whom and when
