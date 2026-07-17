"""
VULNERABLE — CWE-89: SQL Injection.

String interpolation in SQL queries. NEVER use this in production.
"""
from __future__ import annotations

import sqlite3
import tempfile

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()

# Use a file-based DB so connections from different threads share data
_db_path = tempfile.mktemp(suffix=".forgeguard-vuln.db")


def _init_db():
    conn = sqlite3.connect(_db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
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
    query = f"SELECT id, name, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": row[0], "name": row[1], "email": row[2]}
