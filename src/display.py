"""
Presentación en color de la criticidad de los CVE en la línea de comandos.

Muestra cada CVE con su puntuación CVSS y su severidad coloreada mediante
códigos ANSI (crítico en rojo, alto en naranja, etc.).
"""
from __future__ import annotations

import os
import sys

from src.schema import ScanResult

# Colores ANSI
RESET = "\033[0m"
BOLD = "\033[1m"
COLORS = {
    "CRITICAL": "\033[97;41m",  # blanco sobre rojo
    "HIGH": "\033[91m",         # rojo
    "MEDIUM": "\033[33m",       # amarillo/naranja
    "LOW": "\033[32m",          # verde
    None: "\033[90m",           # gris
}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def severity_label(cvss, severity) -> str:
    sev = (severity or "N/D").upper()
    score = f"{cvss:.1f}" if cvss is not None else "N/D"
    text = f"[{sev} · CVSS {score}]"
    if not _supports_color():
        return text
    color = COLORS.get(sev if sev in COLORS else None, COLORS[None])
    return f"{color}{BOLD} {sev} · CVSS {score} {RESET}"


def colored_summary(scan: ScanResult) -> str:
    lines: list[str] = []
    for h in scan.hosts:
        label = h.address + (f" ({h.hostname})" if h.hostname else "")
        lines.append(f"Host {label} [{h.state}]")
        for s in h.services:
            extra = " ".join(x for x in (s.product, s.version) if x)
            extra = f" - {extra}" if extra else ""
            lines.append(f"  {s.port}/{s.protocol} {s.state} {s.service or ''}{extra}".rstrip())
            for v in s.vulnerabilities:
                lines.append(f"      {v.id} {severity_label(v.cvss, v.severity)}")
    return "\n".join(lines) if lines else "Sin hosts activos."
