"""
VULNERABLE — CWE-352: Cross-Site Request Forgery.

No CSRF protection on state-changing endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Form

router = APIRouter()

# In-memory "database"
items: list[dict] = []


@router.post("/items")
def create_item(name: str = Form(...), value: str = Form(...)):
    """Create an item. VULNERABLE: no CSRF token validation."""
    # BAD: no CSRF check — CWE-352
    # An attacker can forge a POST request from another site
    items.append({"name": name, "value": value})
    return {"status": "created", "count": len(items)}


@router.get("/items")
def list_items():
    """List all items."""
    return {"items": items}