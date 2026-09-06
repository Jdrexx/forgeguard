"""
ForgeGuard — main entry point for CLI.

Usage:
    python -m forgeguard scan-results/
    python -m forgeguard scan-results/ --policy policy/security-policy.yaml
"""

from __future__ import annotations

import sys

from security.policy import cli

if __name__ == "__main__":
    cli()