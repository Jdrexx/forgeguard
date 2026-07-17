"""
FIXED — CWE-22: Path Traversal (remediated).

Uses path containment check to ensure the resolved path stays within BASE_DIR.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()
BASE_DIR = os.path.abspath("/tmp/forgeguard-files")
os.makedirs(BASE_DIR, exist_ok=True)


@router.get("/read")
def read_file(filename: str = Query(..., description="File to read (safe)")):
    """Read a file from the data directory. SAFE: path containment check."""
    # Compute absolute path and verify it's within BASE_DIR
    requested = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not requested.startswith(BASE_DIR):
        raise HTTPException(status_code=403, detail="Path traversal detected")
    if not os.path.exists(requested):
        raise HTTPException(status_code=404, detail="File not found")
    with open(requested) as f:
        return {"content": f.read()}
