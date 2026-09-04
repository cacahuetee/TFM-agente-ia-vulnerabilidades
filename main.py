"""Punto de entrada por línea de comandos.

Ejemplos:
    python main.py parse     data/samples/sample_nmap.xml
    python main.py enrich    data/samples/sample_nmap.xml --offline      # CVEs en color
    python main.py interpret data/samples/sample_nmap.xml --enrich       # flujo completo
    python main.py prioritize data/samples/sample_nmap.xml --offline     # ranking por riesgo
    python main.py evaluate  --mock                                      # comparativa
"""
from __future__ import annotations

import argparse
import sys

from src.parsers.dispatch import parse_scan


def cmd_parse(args) -> None:
    scan = parse_scan(args.file)
    print(scan.to_json() if args.json else scan.summary())


def cmd_enrich(args) -> None:
    from src.knowledge.cve import CVELookup
    from src.display import colored_summary
    scan = parse_scan(args.file)
    scan = CVELookup(use_network=not args.offline).enrich_scan(scan)
    print(scan.to_json() if args.json else colored_summary(scan))


def cmd_prioritize(args) -> None:
    from src.knowledge.cve import CVELookup
    from src.tasks.prioritize import prioritized_findings
    from src.display import severity_label
    scan = parse_scan(args.file)
    scan = CVELookup(use_network=not args.offline).enrich_scan(scan)
    findings = prioritized_findings(scan)
    if not findings:
        print("Sin vulnerabilidades conocidas en los datos.")
        return
    print("Vulnerabilidades ordenadas por riesgo:")
    for i, f in enumerate(findings, 1):
        print(f"{i:2}. {f.cve.id}  {severity_label(f.cve.cvss, f.cve.severity)}  "
              f"-> {f.host} {f.port}/{f.service}")


def cmd_interpret(args) -> None:
    from src import config
    config.ensure_api_key_interactive()
    from src.tasks.interpret_scan import interpret_scan_file
    result = interpret_scan_file(args.file, enrich=args.enrich)
    print(f"[modelo: {result.model} | latencia: {result.response.latency_s:.2f}s]\n")
    print(result.response.text)


def cmd_logs(args) -> None:
    from src import config
    config.ensure_api_key_interactive()
    from src.tasks.analyze_logs import analyze_logs_file
    result = analyze_logs_file(args.file)
    print(f"[modelo: {result.model} | latencia: {result.response.latency_s:.2f}s]\n")
    print(result.response.text)


def cmd_evaluate(args) -> None:
    from evaluation.run_eval import run, DEFAULT_MODELS, EVAL_DIR
    from pathlib import Path
    if not args.mock:
        from src import config
        config.ensure_api_key_interactive()
    models = [m.strip() for m in (args.models or ",".join(DEFAULT_MODELS)).split(",") if m.strip()]
    run(models, offline=args.offline or args.mock, mock=args.mock, out_dir=Path(EVAL_DIR) / "resultados")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Agente de apoyo a auditorías de seguridad (TFM)")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("parse", help="Parsea un escaneo (Nmap o Nessus)")
    a.add_argument("file"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_parse)

    b = sub.add_parser("enrich", help="Parsea y añade CVEs (en color)")
    b.add_argument("file"); b.add_argument("--json", action="store_true")
    b.add_argument("--offline", action="store_true")
    b.set_defaults(func=cmd_enrich)

    r = sub.add_parser("prioritize", help="Ordena las vulnerabilidades por riesgo")
    r.add_argument("file"); r.add_argument("--offline", action="store_true")
    r.set_defaults(func=cmd_prioritize)

    c = sub.add_parser("interpret", help="Interpreta el escaneo con el LLM")
    c.add_argument("file"); c.add_argument("--enrich", action="store_true")
    c.set_defaults(func=cmd_interpret)

    g = sub.add_parser("logs", help="Analiza un fichero de logs con el LLM")
    g.add_argument("file")
    g.set_defaults(func=cmd_logs)

    e = sub.add_parser("evaluate", help="Evalúa y compara modelos")
    e.add_argument("--models", default=""); e.add_argument("--offline", action="store_true")
    e.add_argument("--mock", action="store_true")
    e.set_defaults(func=cmd_evaluate)
    return p


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
