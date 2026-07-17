"""
FIXED — CWE-502: Unsafe Deserialization (remediated).

Uses JSON instead of pickle. No arbitrary code execution vector.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Body

router = APIRouter()


@router.post("/deserialize")
def deserialize(data: str = Body(..., description="JSON string to parse")):
    """Deserialize JSON data. SAFE: JSON instead of pickle."""
    # GOOD: JSON parsing is safe — no arbitrary code execution
    try:
        obj = json.loads(data)
        return {"result": obj}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}
