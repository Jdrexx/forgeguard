"""
ForgeGuard — sample FastAPI application with vulnerable/fixed mirror.

This app exists as a test fixture for the ForgeGuard pipeline.
In production (DEMO_MODE=0), only the fixed endpoints are available.
Set DEMO_MODE=1 to expose the deliberately vulnerable endpoints.
"""
from __future__ import annotations

import os

from fastapi import FastAPI

app = FastAPI(
    title="ForgeGuard Demo App",
    version="0.1.0",
    description="Test fixture for the ForgeGuard DevSecOps pipeline",
)

DEMO_MODE = os.environ.get("DEMO_MODE", "0") == "1"


# ── health checks (always available) ───────────────────────────────────

@app.get("/livez")
async def livez():
    """Liveness probe."""
    return {"status": "alive"}


@app.get("/readyz")
async def readyz():
    """Readiness probe — checks that the app is ready to serve."""
    return {"status": "ready", "demo_mode": DEMO_MODE}


# ── fixed endpoints (always available) ─────────────────────────────────

from .fixed import sqli as fixed_sqli
from .fixed import xss as fixed_xss
from .fixed import traversal as fixed_traversal
from .fixed import csrf as fixed_csrf
from .fixed import pickle_rce as fixed_pickle
from .fixed import info_leak as fixed_info_leak

app.include_router(fixed_sqli.router, prefix="/api")
app.include_router(fixed_xss.router, prefix="/api")
app.include_router(fixed_traversal.router, prefix="/api")
app.include_router(fixed_csrf.router, prefix="/api")
app.include_router(fixed_pickle.router, prefix="/api")
app.include_router(fixed_info_leak.router, prefix="/api")


# ── vulnerable endpoints (DEMO_MODE only) ──────────────────────────────

if DEMO_MODE:
    from .vulnerable import sqli as vuln_sqli
    from .vulnerable import xss as vuln_xss
    from .vulnerable import traversal as vuln_traversal
    from .vulnerable import info_leak as vuln_info_leak
    from .vulnerable import csrf as vuln_csrf
    from .vulnerable import pickle_rce as vuln_pickle

    app.include_router(vuln_sqli.router, prefix="/vuln")
    app.include_router(vuln_xss.router, prefix="/vuln")
    app.include_router(vuln_traversal.router, prefix="/vuln")
    app.include_router(vuln_info_leak.router, prefix="/vuln")
    app.include_router(vuln_csrf.router, prefix="/vuln")
    app.include_router(vuln_pickle.router, prefix="/vuln")
