"""
Integración de MITRE ATT&CK y OWASP (objetivo 4).

Asocia los servicios detectados con técnicas de MITRE ATT&CK y, cuando aplica,
con categorías de OWASP, mediante un mapeo curado que funciona sin conexión.
Es un punto de partida ampliable: no pretende ser exhaustivo, sino aportar
contexto contrastable a la interpretación.

Referencias: MITRE ATT&CK (Strom et al., 2018), OWASP Top 10 (2021).
"""
from __future__ import annotations

from src.schema import ScanResult

# Mapeo por nombre de servicio (en minúsculas) -> técnicas ATT&CK y notas OWASP.
SERVICE_MAP: dict[str, dict] = {
    "ftp": {
        "attack": ["T1071 (Application Layer Protocol)", "T1078 (Valid Accounts)"],
        "owasp": ["A07:2021 Identification and Authentication Failures"],
        "nota": "FTP suele transmitir credenciales sin cifrar.",
    },
    "ssh": {
        "attack": ["T1021.004 (Remote Services: SSH)", "T1110 (Brute Force)"],
        "owasp": [],
        "nota": "Acceso remoto; vigilar fuerza bruta y versiones antiguas.",
    },
    "telnet": {
        "attack": ["T1021 (Remote Services)", "T1040 (Network Sniffing)"],
        "owasp": ["A02:2021 Cryptographic Failures"],
        "nota": "Telnet transmite en claro; desaconsejado.",
    },
    "http": {
        "attack": ["T1190 (Exploit Public-Facing Application)"],
        "owasp": ["A05:2021 Security Misconfiguration", "A06:2021 Vulnerable and Outdated Components"],
        "nota": "Servicio web expuesto; revisar versión y configuración.",
    },
    "https": {
        "attack": ["T1190 (Exploit Public-Facing Application)"],
        "owasp": ["A05:2021 Security Misconfiguration", "A02:2021 Cryptographic Failures"],
        "nota": "Revisar configuración TLS y versión del servidor.",
    },
    "mysql": {
        "attack": ["T1190 (Exploit Public-Facing Application)", "T1078 (Valid Accounts)"],
        "owasp": ["A05:2021 Security Misconfiguration"],
        "nota": "Base de datos expuesta a la red; no debería ser accesible externamente.",
    },
    "microsoft-ds": {
        "attack": ["T1021.002 (SMB/Windows Admin Shares)", "T1210 (Exploitation of Remote Services)"],
        "owasp": [],
        "nota": "SMB expuesto; históricamente vector de propagación (p. ej. ransomware).",
    },
    "ms-wbt-server": {
        "attack": ["T1021.001 (Remote Desktop Protocol)", "T1110 (Brute Force)"],
        "owasp": [],
        "nota": "RDP expuesto; objetivo frecuente de fuerza bruta.",
    },
    "msrpc": {
        "attack": ["T1021 (Remote Services)"],
        "owasp": [],
        "nota": "RPC de Windows; limitar exposición.",
    },
}


def map_service(service: str | None) -> dict | None:
    if not service:
        return None
    return SERVICE_MAP.get(service.lower())


def attack_owasp_context(scan: ScanResult) -> str:
    """Genera un texto con el contexto ATT&CK/OWASP de los servicios detectados."""
    lines: list[str] = []
    seen: set[str] = set()
    for host in scan.hosts:
        for s in host.services:
            info = map_service(s.service)
            if not info or s.service in seen:
                continue
            seen.add(s.service)
            attack = "; ".join(info["attack"]) or "-"
            owasp = "; ".join(info["owasp"]) or "-"
            lines.append(f"- {s.service}: ATT&CK: {attack} | OWASP: {owasp}. {info['nota']}")
    if not lines:
        return ""
    return "Contexto de referencia (MITRE ATT&CK / OWASP):\n" + "\n".join(lines)
