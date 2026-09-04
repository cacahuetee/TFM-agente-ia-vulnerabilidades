"""
Métricas objetivas para evaluar las respuestas del sistema.

Todas son deterministas y comprobables (no dependen de un juicio humano ni
de otro modelo), lo que las hace reproducibles para el capítulo de evaluación.

- Cobertura: qué proporción de los elementos esperados (ground truth) aparece
  en la respuesta. Mide la completitud.
- CVEs no fundamentados: identificadores CVE mencionados en la respuesta que
  NO están entre los datos proporcionados al modelo. Es un indicador de
  contenido no fundamentado (alucinación).
"""
from __future__ import annotations

import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> set[str]:
    return {m.upper() for m in CVE_RE.findall(text or "")}


def coverage(text: str, expected: list[str]) -> dict:
    """Proporción de elementos esperados presentes en el texto (case-insensitive)."""
    t = (text or "").lower()
    hits = [e for e in expected if e.lower() in t]
    ratio = len(hits) / len(expected) if expected else 0.0
    return {
        "expected": len(expected),
        "covered": len(hits),
        "coverage": round(ratio, 3),
        "missing": [e for e in expected if e.lower() not in t],
    }


def unsupported_cves(text: str, supported: set[str]) -> set[str]:
    """CVEs mencionados que no estaban entre los datos aportados al modelo."""
    mentioned = extract_cves(text)
    sup = {c.upper() for c in supported}
    return mentioned - sup
