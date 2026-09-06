"""
FIXED — CWE-200: Information Exposure (remediated).

Debug endpoints fully stripped. No configuration leakage.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()

# Intentionally empty — debug endpoints are removed in production.
# No /debug/config, no /debug/info, no stack trace exposure.
# Environment variables are never leaked through API responses.