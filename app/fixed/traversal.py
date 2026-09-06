"""
FIXED — CWE-22: Path Traversal (remediated).

Uses path containment check to ensure the resolved path stays within BASE_DIR.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()
PROJECT_ROOT = os.path.abspath("/tmp/forgeguard-files")
os.makedirs(PROJECT_ROOT, exist_ok=True)


@router.get("/read")
def read_file(filename: str = Query(..., description="File to read (safe)")):
    """Read a file from the data directory. SAFE: path containment check."""
    # Compute the resolved path and verify it is still INSIDE the root.
    # NOTE: the historical startswith(BASE_DIR) prefix check was bypassable
    # with a sibling like /tmp/forgeguard-files-evil/... — a prefix without a
    # path-separator boundary is not containment. is_relative_to() (py3.9+)
    # resolves both sides and checks the real ancestor relation.
    requested = os.path.realpath(os.path.join(PROJECT_ROOT, filename))
    if not Path(requested).is_relative_to(Path(PROJECT_ROOT)):
        raise HTTPException(status_code=403, detail="Path traversal detected")
    if not os.path.exists(requested):
        raise HTTPException(status_code=404, detail="File not found")
    with open(requested) as f:
        return {"content": f.read()}