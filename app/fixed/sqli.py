"""
FIXED — CWE-89: SQL Injection (remediated).

Uses parameterized queries to prevent SQL injection.
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()

# Use a private temporary directory so the database name cannot be claimed by
# another process between path creation and sqlite opening.
_db_directory = tempfile.TemporaryDirectory(prefix="forgeguard-fixed-")
_db_path = Path(_db_directory.name) / "users.db"


def _init_db():
    with sqlite3.connect(_db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
        conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@example.com')")
        conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@example.com')")


_init_db()


@router.get("/user")
def get_user(user_id: str = Query(..., description="User ID (parameterized)")):
    """Fetch a user by ID. SAFE: uses parameterized query."""
    with sqlite3.connect(_db_path) as conn:
        # GOOD: parameterized query prevents injection
        row = conn.execute(
            "SELECT id, name, email FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": row[0], "name": row[1], "email": row[2]}
