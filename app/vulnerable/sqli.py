"""
VULNERABLE — CWE-89: SQL Injection.

String interpolation in SQL queries. NEVER use this in production.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()

# A private temp directory (0700). The vulnerability this module teaches is
# SQL injection — an insecure DB path (tempfile.mktemp) would be a second,
# unrelated CWE-377 issue muddying the demo, so the fixture keeps a safe
# private path even though the query is deliberately interpolated.
_db_dir = tempfile.mkdtemp(prefix="forgeguard-vuln-")
_db_path = str(Path(_db_dir) / "app.db")


def _init_db():
    conn = sqlite3.connect(_db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
    )
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@example.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@example.com')")
    conn.commit()
    conn.close()


_init_db()


@router.get("/user")
def get_user(user_id: str = Query(..., description="User ID (vulnerable to SQLi)")):
    """Fetch a user by ID. VULNERABLE: string interpolation in SQL."""
    conn = sqlite3.connect(_db_path)
    cursor = conn.cursor()
    # BAD: string interpolation — CWE-89
    # This interpolated query is the DELIBERATE vulnerability this fixture
    # exists to teach. Mounted only when DEMO_MODE=1 (app/main.py); the
    # fixed/sqli.py router is the production path.
    query = f"SELECT id, name, email FROM users WHERE id = '{user_id}'"
    # nosemgrep: sqlalchemy-execute-raw-query
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": row[0], "name": row[1], "email": row[2]}