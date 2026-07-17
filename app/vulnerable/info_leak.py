"""
VULNERABLE — CWE-200: Information Exposure.

Debug endpoint that exposes configuration and environment variables.
"""
from __future__ import annotations

import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/debug/config")
def debug_config():
    """Expose application configuration. VULNERABLE: leaks secrets."""
    # BAD: exposes all environment variables including secrets — CWE-200
    return {
        "environment": dict(os.environ),
        "config": {
            "database_url": os.environ.get("DATABASE_URL", "postgres://user:pass@localhost/db"),
            "secret_key": os.environ.get("SECRET_KEY", "dev-secret-key-12345"),
            "api_keys": os.environ.get("API_KEYS", "sk-1234,sk-5678"),
        },
        "sys_path": __import__("sys").path,
        "python_version": __import__("sys").version,
    }


@router.get("/debug/error")
def debug_error():
    """Deliberately raises an exception with stack trace. VULNERABLE: leaks internals."""
    raise Exception(
        "Debug error — here's the stack trace with all local variables exposed"
    )
