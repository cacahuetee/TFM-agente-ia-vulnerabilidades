"""
Generación de informes.

A partir de un ScanResult (opcionalmente enriquecido con CVEs) y de la
interpretación del modelo, produce un informe en Markdown y en HTML usando
plantillas Jinja2. El HTML es autocontenido y puede imprimirse a PDF desde
el navegador, sin dependencias adicionales.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.schema import ScanResult

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def build_context(scan: ScanResult, interpretation: str | None = None,
                  meta: dict | None = None) -> dict:
    """Prepara los datos que consumen las plantillas."""
    n_hosts = len(scan.hosts)
    services = [s for h in scan.hosts for s in h.services]
    vulns = [v for s in services for v in s.vulnerabilities]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SIN CLASIFICAR": 0}
    for v in vulns:
        key = (v.severity or "SIN CLASIFICAR").upper()
        counts[key] = counts.get(key, 0) + 1

    highest = None
    for v in vulns:
        if SEVERITY_ORDER.get(v.severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = v.severity

    meta = meta or {}
    return {
        "title": meta.get("title", "Informe de análisis de vulnerabilidades"),
        "author": meta.get("author", ""),
        "date": meta.get("date", datetime.now().strftime("%d/%m/%Y %H:%M")),
        "tool": scan.source_tool,
        "command": scan.command or "",
        "n_hosts": n_hosts,
        "n_services": len(services),
        "n_vulns": len(vulns),
        "counts": counts,
        "highest": highest or "N/D",
        "hosts": scan.hosts,
        "interpretation": interpretation,
    }


def render_markdown(context: dict) -> str:
    return _env().get_template("report.md.j2").render(**context)


def render_html(context: dict) -> str:
    return _env().get_template("report.html.j2").render(**context)


def generate_report(scan: ScanResult, interpretation: str | None = None,
                    meta: dict | None = None, out_dir: str | Path = "output",
                    basename: str | None = None) -> dict:
    """Escribe el informe en Markdown y HTML. Devuelve las rutas."""
    ctx = build_context(scan, interpretation, meta)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = basename or f"informe_{stamp}"

    md_path = out / f"{base}.md"
    html_path = out / f"{base}.html"
    md_path.write_text(render_markdown(ctx), encoding="utf-8")
    html_path.write_text(render_html(ctx), encoding="utf-8")
    return {"markdown": str(md_path), "html": str(html_path)}
