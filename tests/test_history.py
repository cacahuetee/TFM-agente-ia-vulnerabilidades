"""Pruebas del historial de análisis por usuario."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import history


def test_save_and_list(tmp_path):
    p = history.save_entry("Gino V", "escaneo", "scan.xml", "deepseek",
                           "texto", report_html="<html>ok</html>", base=tmp_path)
    assert p.exists()
    entries = history.list_entries("Gino V", base=tmp_path)
    assert len(entries) == 1
    e = entries[0]
    assert e["modelo"] == "deepseek" and e["tipo"] == "escaneo"
    assert Path(e["_html_path"]).read_text() == "<html>ok</html>"


def test_history_is_per_user(tmp_path):
    history.save_entry("A", "logs", "a.log", "free", "x", base=tmp_path)
    assert history.list_entries("B", base=tmp_path) == []
    assert len(history.list_entries("A", base=tmp_path)) == 1


def test_delete_entry_removes_files(tmp_path):
    history.save_entry("A", "escaneo", "s.xml", "free", "x", report_html="<p>", base=tmp_path)
    e = history.list_entries("A", base=tmp_path)[0]
    history.delete_entry("A", e["_json"], base=tmp_path)
    assert history.list_entries("A", base=tmp_path) == []
    assert not list((tmp_path / "a").glob("*.html"))
