"""
VULNERABLE — CWE-502: Unsafe Deserialization.

Uses pickle.loads() on user-supplied data. Remote code execution vector.
"""
from __future__ import annotations

import pickle
import base64

from fastapi import APIRouter, Body

router = APIRouter()


@router.post("/deserialize")
def deserialize(data: str = Body(..., description="Base64-encoded pickle data")):
    """Deserialize pickled data. VULNERABLE: unsafe deserialization — CWE-502."""
    # BAD: unpickling user-supplied data — arbitrary code execution
    try:
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return {"result": str(obj)}
    except Exception as e:
        return {"error": str(e)}
