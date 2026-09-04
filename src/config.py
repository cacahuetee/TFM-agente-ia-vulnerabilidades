"""Configuración: clave de API (solo en memoria o entorno) y modelos (YAML).

La clave de OpenRouter NO se guarda en disco por la herramienta:
  - En la web, cada usuario la introduce al entrar y vive en la sesión.
  - En la consola (CLI), se pide al arrancar si no está en el entorno.
  - Opcionalmente, un usuario avanzado puede definirla en un fichero .env
    (ver .env.example) o como variable de entorno, p. ej. en Docker.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import yaml

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ROOT = Path(__file__).resolve().parent.parent

OPENROUTER_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")


def get_api_key() -> str:
    """Clave disponible en el entorno del proceso (variable o .env cargado)."""
    return os.environ.get("OPENROUTER_API_KEY", "")


def set_api_key_for_session(key: str) -> None:
    """Deja la clave disponible SOLO para este proceso (no se escribe en disco)."""
    os.environ["OPENROUTER_API_KEY"] = (key or "").strip()


def ensure_api_key_interactive() -> str:
    """Uso por consola: si no hay clave, la pide y la mantiene solo en memoria."""
    key = get_api_key()
    if key:
        return key
    if not sys.stdin or not sys.stdin.isatty():
        return ""  # sin consola interactiva: no preguntar
    print()
    print("=== Clave de OpenRouter ===")
    print("Solo hace falta para la interpretacion escrita por la IA.")
    print("Consiguela en https://openrouter.ai/keys  (es gratis registrarse).")
    print("La clave NO se guarda: se pedira de nuevo la proxima vez.")
    try:
        entered = input("Pega tu clave (sk-or-...) y pulsa Enter, o dejalo vacio para omitir: ").strip()
    except EOFError:
        entered = ""
    if entered:
        set_api_key_for_session(entered)
        return entered
    print("Continuando sin clave (veras servicios y CVEs, pero no la interpretacion).\n")
    return ""


def load_models_config(path: str | None = None) -> dict:
    cfg_path = Path(path) if path else ROOT / "config" / "models.yaml"
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
