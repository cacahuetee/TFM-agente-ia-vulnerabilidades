"""
Esquema de datos normalizado.

Toda herramienta de entrada (Nmap, Nessus, logs...) se convierte a estas
estructuras, de modo que el resto del sistema no dependa del formato original.
Materializa la capa de herramientas desacoplada del objetivo 2.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional
import json


@dataclass
class CVE:
    """Vulnerabilidad conocida asociada a un servicio."""
    id: str                            # p. ej. CVE-2011-2523
    cvss: Optional[float] = None       # puntuación base CVSS
    severity: Optional[str] = None     # LOW / MEDIUM / HIGH / CRITICAL
    description: Optional[str] = None


@dataclass
class Service:
    """Un servicio detectado en un puerto."""
    port: int
    protocol: str                      # tcp / udp
    state: str                         # open / closed / filtered
    service: Optional[str] = None      # http, ssh, ...
    product: Optional[str] = None      # Apache httpd, OpenSSH, ...
    version: Optional[str] = None
    cpe: list[str] = field(default_factory=list)
    vulnerabilities: list[CVE] = field(default_factory=list)


@dataclass
class Host:
    """Un host analizado."""
    address: str
    hostname: Optional[str] = None
    state: str = "up"
    services: list[Service] = field(default_factory=list)


@dataclass
class ScanResult:
    """Resultado normalizado de un escaneo, independiente de la herramienta."""
    source_tool: str                   # "nmap", "nessus", ...
    command: Optional[str] = None
    hosts: list[Host] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary(self) -> str:
        """Resumen textual compacto para pasar al modelo como contexto."""
        lines: list[str] = []
        for h in self.hosts:
            label = h.address + (f" ({h.hostname})" if h.hostname else "")
            lines.append(f"Host {label} [{h.state}]")
            for s in h.services:
                extra = " ".join(x for x in (s.product, s.version) if x)
                extra = f" - {extra}" if extra else ""
                lines.append(
                    f"  {s.port}/{s.protocol} {s.state} {s.service or ''}{extra}".rstrip()
                )
                for v in s.vulnerabilities:
                    sev = f" [{v.severity}]" if v.severity else ""
                    score = f" CVSS {v.cvss}" if v.cvss is not None else ""
                    lines.append(f"      - {v.id}{score}{sev}")
        return "\n".join(lines) if lines else "Sin hosts activos."
