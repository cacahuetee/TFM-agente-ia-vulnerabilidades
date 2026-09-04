"""
Trazabilidad de las decisiones del sistema (objetivo 6).

Registra cada llamada a un modelo en un fichero JSON-lines, con fecha, tarea,
modelo, latencia y tokens. Permite auditar a posteriori qué hizo el sistema.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from src.config import ROOT

LOG_PATH = ROOT / "data" / "logs" / "runs.jsonl"


def log_call(task: str, model: str, latency_s: float,
             prompt_tokens=None, completion_tokens=None) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "task": task,
        "model": model,
        "latency_s": round(latency_s, 3),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    }
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
