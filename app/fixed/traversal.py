"""
FIXED — CWE-22: Path Traversal (remediated).

Uses path containment check to ensure the resolved path stays within BASE_DIR.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()
_data_directory = tempfile.TemporaryDirectory(prefix="forgeguard-files-")
BASE_DIR = Path(_data_directory.name).resolve()


@router.get("/read")
def read_file(filename: str = Query(..., description="File to read (safe)")):
    """Read a file from the data directory. SAFE: path containment check."""
    requested = (BASE_DIR / filename).resolve()
    if not requested.is_relative_to(BASE_DIR):
        raise HTTPException(status_code=403, detail="Path traversal detected")
    if not requested.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    with requested.open(encoding="utf-8") as f:
        return {"content": f.read()}
