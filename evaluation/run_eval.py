"""
Runner de evaluación (objetivos 7 y 8).

Ejecuta cada caso de prueba contra cada modelo indicado, calcula métricas
objetivas (cobertura, CVEs no fundamentados, latencia y tokens) y escribe:
  - resultados_detalle.csv  : una fila por (caso, modelo)
  - resultados_resumen.csv  : una fila por modelo (medias y totales)

Uso (desde la raíz del proyecto):
    python -m evaluation.run_eval                      # los 4 modelos nombrados
    python -m evaluation.run_eval --models free        # prueba barata
    python -m evaluation.run_eval --mock               # sin red, cliente simulado
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path

from src.parsers.nmap_parser import parse_nmap_xml
from src.knowledge.cve import CVELookup
from src.llm.router import ModelRouter
from src.schema import ScanResult
from src.tasks.interpret_scan import _load_prompt, TASK
from evaluation.metrics import coverage, unsupported_cves

EVAL_DIR = Path(__file__).resolve().parent
CASES_DIR = EVAL_DIR / "cases"
DEFAULT_MODELS = ["deepseek", "qwen", "llama", "mistral"]


def supported_cves(scan: ScanResult) -> set[str]:
    out: set[str] = set()
    for h in scan.hosts:
        for s in h.services:
            for v in s.vulnerabilities:
                out.add(v.id.upper())
    return out


def load_cases() -> list[dict]:
    data = json.loads((EVAL_DIR / "ground_truth.json").read_text(encoding="utf-8"))
    return data["cases"]


def price_of(router: ModelRouter, alias: str) -> tuple[float | None, float | None]:
    m = router.models.get(alias, {})
    return m.get("price_in"), m.get("price_out")


def est_cost(pin, pout, ptok, ctok) -> float | None:
    if pin is None or pout is None or ptok is None or ctok is None:
        return None
    return round(ptok / 1_000_000 * pin + ctok / 1_000_000 * pout, 6)


def run(models: list[str], offline: bool, mock: bool, out_dir: Path, progress=None,
        api_key: str | None = None):
    router = ModelRouter()
    cases = load_cases()
    system, user_template = _load_prompt()

    if mock:
        from evaluation.mock_client import MockClient
        client = MockClient()
    else:
        from src.llm.openrouter_client import OpenRouterClient
        client = OpenRouterClient(api_key=api_key)

    lookup = CVELookup(use_network=not offline)
    from src.parsers.dispatch import parse_scan

    total = len(models) * len(cases)
    done = 0
    detail_rows: list[dict] = []
    failed: list[dict] = []
    for alias in models:
        model_id = router.models.get(alias, {}).get("id", alias)
        pin, pout = price_of(router, alias)
        try:
            for case in cases:
                scan = parse_scan(str(CASES_DIR / case["xml"]))
                scan = lookup.enrich_scan(scan)
                sup = supported_cves(scan)

                user = user_template.format(scan_summary=scan.summary())
                resp = client.chat(model=model_id, system=system, user=user, task="evaluate")

                cov = coverage(resp.text, case["expected"])
                unsup = unsupported_cves(resp.text, sup)

                detail_rows.append({
                    "modelo": alias,
                    "caso": case["name"],
                    "cobertura": cov["coverage"],
                    "cubiertos": cov["covered"],
                    "esperados": cov["expected"],
                    "cves_no_fundamentados": len(unsup),
                    "latencia_s": round(resp.latency_s, 3),
                    "tokens_prompt": resp.prompt_tokens,
                    "tokens_respuesta": resp.completion_tokens,
                    "coste_estimado": est_cost(pin, pout, resp.prompt_tokens, resp.completion_tokens),
                })
                done += 1
                if progress:
                    progress(done, total, f"{alias} · {case['name']}")
                print(f"[{alias:9}] {case['name']:22} cobertura={cov['coverage']:.2f} "
                      f"cve_no_fund={len(unsup)} lat={resp.latency_s:.2f}s")
        except Exception as exc:  # noqa: BLE001
            # un modelo puede no estar disponible (400) o agotar el límite (429):
            # se anota y se continúa con los demás en vez de abortar todo.
            done += len(cases) - len([r for r in detail_rows if r["modelo"] == alias])
            failed.append({"modelo": alias, "id": model_id, "error": str(exc)})
            print(f"[{alias}] OMITIDO: {exc}")
            if progress:
                progress(min(done, total), total, f"{alias} omitido")
            continue

    if not detail_rows:
        raise RuntimeError("Ningún modelo pudo completarse. Revisa los identificadores "
                           "o prueba con el modelo 'free'. Detalle: "
                           + "; ".join(f"{f['modelo']}: {f['error']}" for f in failed))

    out_dir.mkdir(parents=True, exist_ok=True)
    detail_path = out_dir / "resultados_detalle.csv"
    with open(detail_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(detail_rows[0].keys()))
        w.writeheader()
        w.writerows(detail_rows)

    # Resumen por modelo (solo los que se completaron)
    summary_rows: list[dict] = []
    for alias in models:
        rows = [r for r in detail_rows if r["modelo"] == alias]
        if not rows:
            continue  # modelo omitido (fallo o no disponible)
        def col(name):
            return [r[name] for r in rows if r[name] is not None]
        costs = col("coste_estimado")
        summary_rows.append({
            "modelo": alias,
            "casos": len(rows),
            "cobertura_media": round(statistics.mean(col("cobertura")), 3) if rows else 0,
            "cves_no_fundamentados_total": sum(col("cves_no_fundamentados")),
            "latencia_media_s": round(statistics.mean(col("latencia_s")), 3) if rows else 0,
            "tokens_totales": sum(col("tokens_prompt")) + sum(col("tokens_respuesta")),
            "coste_estimado_total": round(sum(costs), 6) if costs else None,
        })

    summary_path = out_dir / "resultados_resumen.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        w.writeheader()
        w.writerows(summary_rows)

    print("\n=== RESUMEN POR MODELO ===")
    for r in summary_rows:
        print(f"{r['modelo']:9} cobertura_media={r['cobertura_media']:.2f} "
              f"cve_no_fund={r['cves_no_fundamentados_total']} "
              f"lat_media={r['latencia_media_s']:.2f}s tokens={r['tokens_totales']}")
    print(f"\nGuardado:\n  {detail_path}\n  {summary_path}")
    return {"summary": summary_rows, "failed": failed}


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluación y comparativa de modelos (TFM)")
    p.add_argument("--models", default=",".join(DEFAULT_MODELS),
                   help="Lista de alias separados por comas (p. ej. deepseek,qwen)")
    p.add_argument("--offline", action="store_true", help="CVEs solo desde caché")
    p.add_argument("--mock", action="store_true", help="Cliente simulado (sin red ni API)")
    p.add_argument("--out", default=str(EVAL_DIR / "resultados"))
    args = p.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    # el modo simulado implica offline
    run(models, offline=args.offline or args.mock, mock=args.mock, out_dir=Path(args.out))


if __name__ == "__main__":
    main()
