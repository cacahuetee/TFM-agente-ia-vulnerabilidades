"""
Historial de análisis por usuario.

Cada vez que un usuario obtiene una interpretación (de un escaneo o de unos
logs) se guarda un registro en data/historial/<usuario>/ con la fecha, el
fichero analizado, el modelo utilizado y el informe generado, para poder
volver a consultarlo o descargarlo después. Materializa la trazabilidad del
objetivo 6 a nivel de usuario.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from src.config import ROOT
from src.users import slug

HISTORY_DIR = ROOT / "data" / "historial"


def _user_dir(user: str, base: Path | None = None) -> Path:
    d = (base or HISTORY_DIR) / slug(user)
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_entry(user: str, kind: str, source_name: str, model: str,
               interpretation: str, report_html: str | None = None,
               extra: dict | None = None, base: Path | None = None) -> Path:
    """Guarda un análisis. `kind` es 'escaneo' o 'logs'. Devuelve la ruta del JSON."""
    now = datetime.now()
    stamp = now.strftime("%Y%m%d_%H%M%S")
    d = _user_dir(user, base)
    record = {
        "fecha": now.strftime("%d/%m/%Y %H:%M"),
        "tipo": kind,
        "fichero": source_name,
        "modelo": model,
        "usuario": user,
        "interpretacion": interpretation,
        **(extra or {}),
    }
    if report_html:
        html_path = d / f"{stamp}_{kind}.html"
        html_path.write_text(report_html, encoding="utf-8")
        record["informe_html"] = html_path.name
    json_path = d / f"{stamp}_{kind}.json"
    json_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return json_path


def list_entries(user: str, base: Path | None = None) -> list[dict]:
    """Entradas del usuario, de la más reciente a la más antigua."""
    d = (base or HISTORY_DIR) / slug(user)
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.json"), reverse=True):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
            rec["_json"] = p.name
            if rec.get("informe_html"):
                rec["_html_path"] = str(d / rec["informe_html"])
            out.append(rec)
        except (json.JSONDecodeError, OSError):
            continue
    return out


def delete_entry(user: str, json_name: str, base: Path | None = None) -> None:
    d = (base or HISTORY_DIR) / slug(user)
    p = d / json_name
    if p.exists():
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
            if rec.get("informe_html"):
                (d / rec["informe_html"]).unlink(missing_ok=True)
        except (json.JSONDecodeError, OSError):
            pass
        p.unlink()
