"""
VULNERABLE — CWE-22: Path Traversal.

User-controlled file path without containment check.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()
BASE_DIR = "/tmp/forgeguard-files"


@router.get("/read")
def read_file(filename: str = Query(..., description="File to read (path traversal vector)")):
    """Read a file from the data directory. VULNERABLE: no path containment check."""
    # BAD: user-controlled path without validation — CWE-22
    filepath = os.path.join(BASE_DIR, filename)
    # Ensure path exists for demo purposes, but contains no sandboxing
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    with open(filepath) as f:
        return {"content": f.read()}
