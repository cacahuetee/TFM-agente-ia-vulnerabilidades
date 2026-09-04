"""Selección de modelo por tarea.

- Por reglas (config/models.yaml): un modelo preferente por tarea.
- Dinámica por métricas (objetivo 3): elige el mejor modelo según los
  resultados de la evaluación (calidad, latencia o coste).
"""
from __future__ import annotations

import csv
from pathlib import Path

from src.config import load_models_config, ROOT


class ModelRouter:
    def __init__(self, models_config: dict | None = None):
        self.cfg = models_config or load_models_config()
        self.models = self.cfg.get("models", {})
        self.routing = self.cfg.get("routing", {})
        self.default = self.cfg.get("default_model")

    def select(self, task: str) -> str:
        alias = self.routing.get(task, self.default)
        return self.models.get(alias, {}).get("id", alias)

    def describe(self, task: str) -> dict:
        alias = self.routing.get(task, self.default)
        info = dict(self.models.get(alias, {}))
        info["alias"] = alias
        info["task"] = task
        return info

    def aliases(self) -> list[str]:
        return list(self.models.keys())

    def id_of(self, alias: str) -> str:
        return self.models.get(alias, {}).get("id", alias)

    def select_by_metrics(self, criterion: str = "cobertura") -> str | None:
        """Mejor modelo según la evaluación: 'cobertura', 'latencia' o 'coste'.

        Devuelve el alias, o None si aún no hay resultados.
        """
        summary = ROOT / "evaluation" / "resultados" / "resultados_resumen.csv"
        if not summary.exists():
            return None
        rows = list(csv.DictReader(open(summary, encoding="utf-8")))
        if not rows:
            return None

        def val(r, col, default):
            try:
                return float(r[col])
            except (KeyError, ValueError, TypeError):
                return default

        if criterion == "latencia":
            best = min(rows, key=lambda r: val(r, "latencia_media_s", 9e9))
        elif criterion == "coste":
            best = min(rows, key=lambda r: val(r, "coste_estimado_total", 9e9))
        else:
            best = max(rows, key=lambda r: val(r, "cobertura_media", -1))
        return best["modelo"]
