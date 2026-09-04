"""Detecta el formato de un fichero de escaneo y llama al parser adecuado."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.nessus_parser import parse_nessus
from src.schema import ScanResult


def parse_scan(path: str) -> ScanResult:
    root = ET.parse(path).getroot()
    tag = root.tag.lower()
    if tag == "nmaprun":
        return parse_nmap_xml(path)
    if "nessus" in tag:
        return parse_nessus(path)
    raise ValueError(f"Formato no reconocido (raíz <{root.tag}>). Se admite Nmap (XML) o Nessus (.nessus).")
