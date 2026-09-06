"""
FIXED — CWE-352: Cross-Site Request Forgery (remediated).

CSRF middleware enabled. State-changing endpoints require token validation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from starlette.requests import Request

router = APIRouter()

items: list[dict] = []


async def verify_csrf_token(request: Request):
    """Dependency that validates CSRF token from header."""
    token = request.headers.get("X-CSRF-Token")
    expected = request.cookies.get("csrf_token")
    if not token or not expected or token != expected:
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    return True


@router.post("/items", dependencies=[Depends(verify_csrf_token)])
def create_item(name: str = Form(...), value: str = Form(...)):
    """Create an item. SAFE: CSRF token required."""
    items.append({"name": name, "value": value})
    return {"status": "created", "count": len(items)}


@router.get("/items")
def list_items():
    """List all items."""
    return {"items": items}