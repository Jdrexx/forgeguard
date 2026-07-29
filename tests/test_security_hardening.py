from pathlib import Path

import pytest
from fastapi import HTTPException

from app.fixed import sqli, traversal


def test_fixed_database_uses_private_temporary_directory():
    database_path = Path(sqli._db_path)

    assert database_path.parent == Path(sqli._db_directory.name)
    assert database_path.name == "users.db"


def test_fixed_traversal_rejects_sibling_prefix(monkeypatch, tmp_path):
    base = tmp_path / "files"
    sibling = tmp_path / "files-private"
    base.mkdir()
    sibling.mkdir()
    (sibling / "secret.txt").write_text("secret", encoding="utf-8")
    monkeypatch.setattr(traversal, "BASE_DIR", base.resolve())

    with pytest.raises(HTTPException) as error:
        traversal.read_file("../files-private/secret.txt")

    assert error.value.status_code == 403


def test_fixed_traversal_reads_regular_file(monkeypatch, tmp_path):
    base = tmp_path / "files"
    base.mkdir()
    (base / "public.txt").write_text("safe", encoding="utf-8")
    monkeypatch.setattr(traversal, "BASE_DIR", base.resolve())

    assert traversal.read_file("public.txt") == {"content": "safe"}
