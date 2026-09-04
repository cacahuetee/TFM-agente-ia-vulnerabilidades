"""Parser del formato .nessus (exportación de Nessus) al esquema normalizado."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from src.schema import ScanResult, Host, Service, CVE

# Severidad numérica de Nessus -> etiqueta
NESSUS_SEV = {"0": None, "1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL"}


def parse_nessus(path: str) -> ScanResult:
    root = ET.parse(path).getroot()
    result = ScanResult(source_tool="nessus")
    report = root.find("Report")
    if report is None:
        return result

    for host_el in report.findall("ReportHost"):
        address = host_el.get("name", "desconocido")
        host = Host(address=address)
        services: dict[int, Service] = {}

        for item in host_el.findall("ReportItem"):
            try:
                port = int(item.get("port", "0"))
            except ValueError:
                port = 0
            protocol = item.get("protocol", "tcp")
            svc_name = item.get("svc_name")

            svc = services.get(port)
            if svc is None:
                svc = Service(port=port, protocol=protocol, state="open", service=svc_name)
                services[port] = svc

            # CVEs y CVSS del hallazgo
            sev = NESSUS_SEV.get(item.get("severity", "0"))
            score_el = item.find("cvss3_base_score")
            if score_el is None:
                score_el = item.find("cvss_base_score")
            score = float(score_el.text) if score_el is not None and score_el.text else None
            for cve_el in item.findall("cve"):
                if cve_el.text:
                    svc.vulnerabilities.append(
                        CVE(id=cve_el.text.strip(), cvss=score, severity=sev)
                    )

        host.services = list(services.values())
        result.hosts.append(host)
    return result
