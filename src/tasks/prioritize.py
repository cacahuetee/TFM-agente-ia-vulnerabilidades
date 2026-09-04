"""
Priorización de vulnerabilidades (objetivo 5, versión base).

Ordena los hallazgos por su severidad CVSS de mayor a menor, para que el
auditor atienda primero lo más crítico.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.schema import ScanResult, CVE

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}


@dataclass
class Finding:
    host: str
    port: int
    service: str
    cve: CVE

    @property
    def sort_key(self):
        return (self.cve.cvss or 0.0, SEVERITY_RANK.get((self.cve.severity or "").upper(), 0))


def prioritized_findings(scan: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    for host in scan.hosts:
        for s in host.services:
            for v in s.vulnerabilities:
                findings.append(Finding(host.address, s.port, s.service or "", v))
    findings.sort(key=lambda f: f.sort_key, reverse=True)
    return findings
