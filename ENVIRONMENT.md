# ForgeGuard — Environment Variables

#

# Reference for all environment variables used by ForgeGuard.

#

# ── Application ────────────────────────────────────────────────────────

DEMO_MODE
Description: Enables vulnerable demo endpoints
Values: 0 (default, production) or 1 (demo mode with vulnerable routes)
Required: No
Default: 0

LOG_LEVEL
Description: Application log level
Values: debug, info, warning, error, critical
Required: No
Default: info

REDIS_URL
Description: Redis connection URL for session storage
Values: redis://host:port/db
Required: No
Default: redis://localhost:6379/0

SECRET_KEY
Description: Application secret key for CSRF and session signing
Values: Any string of at least 32 characters
Required: No
Default: forgeguard-dev-secret

# ── Policy Engine ──────────────────────────────────────────────────────

FORGEGUARD_POLICY_PATH
Description: Path to the security policy YAML
Values: Path
Required: No
Default: policy/security-policy.yaml

FORGEGUARD_ALLOWLIST_PATH
Description: Path to the accepted risks / suppressions YAML
Values: Path
Required: No
Default: policy/accepted-risks.yaml

GITHUB_ACTIONS
Description: Set to "true" to enable GitHub Actions annotations
Values: true, false
Required: No
Default: false

# ── Scoring Weights ────────────────────────────────────────────────────

FORGEGUARD_CRITICAL_WEIGHT
Description: Weight for critical-severity findings
Values: Integer
Required: No
Default: 10

FORGEGUARD_HIGH_WEIGHT
Description: Weight for high-severity findings
Values: Integer
Required: No
Default: 5

FORGEGUARD_MEDIUM_WEIGHT
Description: Weight for medium-severity findings
Values: Integer
Required: No
Default: 2

FORGEGUARD_LOW_WEIGHT
Description: Weight for low-severity findings
Values: Integer
Required: No
Default: 1

# ── Infrastructure ─────────────────────────────────────────────────────

AWS_REGION
Description: AWS region for deployment
Values: us-east-1, us-west-2, eu-west-1, etc.
Required: For AWS deployment
Default: us-east-1

CONTAINER_IMAGE
Description: Container image URI for ECS deployment
Values: ghcr.io/org/repo:tag
Required: For AWS deployment
Default: None