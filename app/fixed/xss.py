"""
FIXED — CWE-79: Cross-Site Scripting (remediated).

Uses output encoding via Jinja2 autoescaping or manual HTML escaping.
"""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/greet", response_class=HTMLResponse)
def greet(name: str = Query(..., description="Name to greet (escaped)")):
    """Return an HTML greeting. SAFE: user input is HTML-escaped."""
    safe_name = escape(name, quote=True)
    return HTMLResponse(f"<html><body><h1>Hello, {safe_name}!</h1></body></html>")