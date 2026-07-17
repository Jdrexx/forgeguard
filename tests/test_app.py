"""
ForgeGuard — app fixture tests.

Tests ensure the demo app starts, serves health checks, and that the
vulnerable endpoints are properly quarantined behind DEMO_MODE.
Uses TestClient for actual HTTP-level verification.
"""
from __future__ import annotations

import os
import sys
from importlib import reload

import pytest
from fastapi.testclient import TestClient


# ── Production Mode (DEMO_MODE=0) ──────────────────────────────────────

def _make_app(demo_mode: str):
    """Create a fresh app instance with the given DEMO_MODE."""
    os.environ["DEMO_MODE"] = demo_mode
    for mod in list(sys.modules.keys()):
        if "app" in mod:
            del sys.modules[mod]
    import app.main
    reload(app.main)
    return app.main.app


@pytest.fixture
def prod_client():
    app = _make_app("0")
    return TestClient(app)


@pytest.fixture
def demo_client():
    app = _make_app("1")
    return TestClient(app)


def test_livez_prod(prod_client):
    resp = prod_client.get("/livez")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}


def test_readyz_prod(prod_client):
    resp = prod_client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["demo_mode"] is False


def test_readyz_demo(demo_client):
    resp = demo_client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["demo_mode"] is True


def test_vulnerable_endpoints_blocked_in_prod(prod_client):
    """In production, /vuln/* should return 404."""
    resp = prod_client.get("/vuln/user?user_id=1")
    assert resp.status_code == 404

    resp = prod_client.get("/vuln/greet?name=test")
    assert resp.status_code == 404

    resp = prod_client.get("/vuln/read?filename=test.txt")
    assert resp.status_code == 404


def test_vulnerable_endpoints_available_in_demo(demo_client):
    """In demo mode, /vuln/* should be accessible."""
    resp = demo_client.get("/vuln/user?user_id=1")
    assert resp.status_code == 200

    resp = demo_client.get("/vuln/greet?name=World")
    assert resp.status_code == 200

    resp = demo_client.get("/vuln/read?filename=nonexistent")
    # Should 404 (file not found), not 405 (method not allowed)
    assert resp.status_code in (200, 404)


def test_fixed_endpoints_always_available(prod_client):
    """Fixed endpoints should work in production mode."""
    resp = prod_client.get("/api/user?user_id=1")
    assert resp.status_code in (200, 404)  # 200 if found, 404 if not

    resp = prod_client.get("/api/greet?name=World")
    assert resp.status_code == 200

    resp = prod_client.get("/api/items")
    assert resp.status_code == 200


def test_vulnerable_endpoints_produce_expected_responses(demo_client):
    """Verify vulnerable endpoints behave as tagged vulnerabilities."""
    # XSS — should return unescaped HTML
    resp = demo_client.get("/vuln/greet?name=<script>alert(1)</script>")
    assert resp.status_code == 200
    body = resp.text
    # Vulnerable: unescaped content
    assert "<script>alert(1)</script>" in body

    # SQLi — should work but is vulnerable
    resp = demo_client.get("/vuln/user?user_id=1")
    assert resp.status_code == 200

    # SQL injection: 1' OR '1'='1 should return a user
    resp = demo_client.get("/vuln/user?user_id=1%27%20OR%20%271%27=%271")
    assert resp.status_code == 200


def test_info_leak_blocked_in_prod(prod_client):
    """Debug endpoints should not exist in production."""
    resp = prod_client.get("/api/debug/config")
    assert resp.status_code == 404

    resp = prod_client.get("/api/debug/error")
    assert resp.status_code == 404
