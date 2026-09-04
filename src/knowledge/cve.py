"""
Integración con la base de vulnerabilidades (NVD / CVE).

Enriquece cada servicio detectado con las vulnerabilidades conocidas
asociadas a su producto/versión o a su CPE. Consulta la API 2.0 de la NVD.

Diseño con caché primero:
  - Antes de consultar la red, se busca en un caché local (JSON).
  - Los resultados nuevos se guardan en ese caché.
Esto evita repetir consultas, respeta los límites de la NVD y permite
ejecutar la evaluación de forma reproducible y sin conexión.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import requests

from src import config
from src.schema import ScanResult, Service, CVE

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = config.ROOT / "data" / "cache" / "cve_cache.json"


class CVELookup:
    def __init__(self, cache_path: Path | None = None, use_network: bool = True,
                 api_key: str | None = None, max_per_service: int = 5):
        self.cache_path = Path(cache_path) if cache_path else CACHE_PATH
        self.use_network = use_network
        self.api_key = api_key or config.NVD_API_KEY
        self.max_per_service = max_per_service
        self.cache = self._load_cache()

    # ---------- caché ----------
    def _load_cache(self) -> dict:
        if self.cache_path.exists():
            with open(self.cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self.cache, f, indent=2, ensure_ascii=False)

    # ---------- consulta ----------
    def _query_nvd(self, params: dict) -> list[CVE]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
        resp.raise_for_status()
        return self._parse_nvd(resp.json())

    @staticmethod
    def _parse_nvd(data: dict) -> list[CVE]:
        out: list[CVE] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), None)
            score = severity = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    score = m.get("cvssData", {}).get("baseScore")
                    severity = (m.get("cvssData", {}).get("baseSeverity")
                                or m.get("baseSeverity"))
                    break
            out.append(CVE(id=cve_id, cvss=score, severity=severity, description=desc))
        return out

    def by_cpe(self, cpe23: str) -> list[CVE]:
        key = f"cpe::{cpe23}"
        if key in self.cache:
            return [CVE(**c) for c in self.cache[key]]
        if not self.use_network:
            return []
        cves = self._query_nvd({"cpeName": cpe23, "resultsPerPage": self.max_per_service})
        self.cache[key] = [c.__dict__ for c in cves]
        time.sleep(6)  # respeta el límite de la NVD sin clave
        return cves

    def by_keyword(self, product: str, version: str | None) -> list[CVE]:
        term = " ".join(x for x in (product, version) if x)
        key = f"kw::{term.lower()}"
        if key in self.cache:
            return [CVE(**c) for c in self.cache[key]]
        if not self.use_network:
            return []
        cves = self._query_nvd({"keywordSearch": term, "resultsPerPage": self.max_per_service})
        self.cache[key] = [c.__dict__ for c in cves]
        time.sleep(6)
        return cves

    # ---------- enriquecimiento ----------
    def enrich_service(self, svc: Service) -> Service:
        cves: list[CVE] = []
        if svc.cpe:
            for cpe in svc.cpe:
                cpe23 = cpe.replace("cpe:/", "cpe:2.3:") if cpe.startswith("cpe:/") else cpe
                cves.extend(self.by_cpe(cpe23))
        elif svc.product:
            cves.extend(self.by_keyword(svc.product, svc.version))
        # ordena por CVSS descendente y recorta
        cves.sort(key=lambda c: (c.cvss or 0), reverse=True)
        svc.vulnerabilities = cves[: self.max_per_service]
        return svc

    def enrich_scan(self, scan: ScanResult) -> ScanResult:
        for host in scan.hosts:
            for svc in host.services:
                self.enrich_service(svc)
        self.save_cache()
        return scan
