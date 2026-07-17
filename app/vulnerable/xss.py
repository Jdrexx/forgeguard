"""
VULNERABLE — CWE-79: Cross-Site Scripting.

Returns unencoded user input directly in the response body.
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/greet", response_class=HTMLResponse)
def greet(name: str = Query(..., description="Name to greet (XSS vector)")):
    """Return an HTML greeting. VULNERABLE: unencoded user input."""
    # BAD: user input injected directly into HTML — CWE-79
    return HTMLResponse(f"<html><body><h1>Hello, {name}!</h1></body></html>")
