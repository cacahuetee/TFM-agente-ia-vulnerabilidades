"""
Gestión de usuarios locales.

Cada persona que usa la herramienta elige (o crea) su nombre al arrancar. Ese
nombre figura como autor en los informes que se descargan. Los nombres se
guardan en data/usuarios.json, en el propio equipo.

Aquí NO se guarda ninguna clave de API: la clave de OpenRouter la introduce
cada usuario en cada sesión y solo vive en memoria mientras la web está abierta.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from src.config import ROOT

USERS_PATH = ROOT / "data" / "usuarios.json"
MAX_NAME_LEN = 60


def _normalize(name: str) -> str:
    """Limpia espacios repetidos y recorta la longitud."""
    return re.sub(r"\s+", " ", (name or "").strip())[:MAX_NAME_LEN]


def load_users(path: Path | None = None) -> list[str]:
    """Devuelve la lista de nombres guardados (vacía si aún no hay ninguno)."""
    p = path or USERS_PATH
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    users = data.get("usuarios", []) if isinstance(data, dict) else []
    return [u for u in users if isinstance(u, str) and u.strip()]


def save_users(users: list[str], path: Path | None = None) -> None:
    p = path or USERS_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"usuarios": users}, ensure_ascii=False, indent=2),
                 encoding="utf-8")


def add_user(name: str, path: Path | None = None) -> str:
    """Añade un usuario (sin duplicados, ignorando mayúsculas) y devuelve el
    nombre tal y como queda guardado."""
    clean = _normalize(name)
    if not clean:
        raise ValueError("El nombre no puede estar vacío.")
    users = load_users(path)
    for existing in users:
        if existing.casefold() == clean.casefold():
            return existing  # ya existía: se reutiliza
    users.append(clean)
    save_users(users, path)
    return clean


def remove_user(name: str, path: Path | None = None) -> list[str]:
    users = [u for u in load_users(path) if u.casefold() != (name or "").casefold()]
    save_users(users, path)
    return users


def slug(name: str) -> str:
    """Versión del nombre apta para nombres de fichero (informe_<slug>.html)."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", _normalize(name)).strip("_")
    return s.lower() or "usuario"
