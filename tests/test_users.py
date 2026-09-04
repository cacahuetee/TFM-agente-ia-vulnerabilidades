"""Pruebas del registro local de usuarios (nombre que firma los informes)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import users


def test_no_users_at_start(tmp_path):
    assert users.load_users(tmp_path / "u.json") == []


def test_add_user_and_persist(tmp_path):
    p = tmp_path / "u.json"
    assert users.add_user("  Gino   Veronesse ", p) == "Gino Veronesse"
    assert users.load_users(p) == ["Gino Veronesse"]


def test_add_user_ignores_duplicates_case_insensitive(tmp_path):
    p = tmp_path / "u.json"
    users.add_user("Elsa Ferreras", p)
    assert users.add_user("elsa ferreras", p) == "Elsa Ferreras"
    assert users.load_users(p) == ["Elsa Ferreras"]


def test_add_empty_user_fails(tmp_path):
    with pytest.raises(ValueError):
        users.add_user("   ", tmp_path / "u.json")


def test_remove_user(tmp_path):
    p = tmp_path / "u.json"
    users.add_user("A", p); users.add_user("B", p)
    assert users.remove_user("a", p) == ["B"]


def test_slug_for_filenames():
    assert users.slug("Gino Alberto Veronesse") == "gino_alberto_veronesse"
    assert users.slug("") == "usuario"


def test_report_author_comes_from_meta():
    from src.reporting.report import build_context
    from src.schema import ScanResult
    ctx = build_context(ScanResult(source_tool="nmap", hosts=[]), meta={"author": "Gino"})
    assert ctx["author"] == "Gino"
