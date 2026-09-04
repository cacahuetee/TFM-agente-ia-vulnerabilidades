"""Pruebas unitarias del núcleo (parser, esquema, métricas, priorización, router)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parsers.nmap_parser import parse_nmap_string
from src.parsers.dispatch import parse_scan
from src.schema import ScanResult, Host, Service, CVE
from src.tasks.prioritize import prioritized_findings
from src.knowledge.attack_owasp import attack_owasp_context
from evaluation.metrics import coverage, unsupported_cves, extract_cves

NMAP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sV">
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2"/></port></ports>
  </host>
</nmaprun>"""


def test_parse_nmap_basic():
    scan = parse_nmap_string(NMAP_XML)
    assert scan.source_tool == "nmap"
    assert len(scan.hosts) == 1
    assert scan.hosts[0].services[0].port == 22
    assert scan.hosts[0].services[0].service == "ssh"


def test_dispatch_nessus():
    scan = parse_scan("data/samples/sample_nessus.nessus")
    assert scan.source_tool == "nessus"
    assert any(v.id == "CVE-2014-0160" for h in scan.hosts for s in h.services for v in s.vulnerabilities)


def test_coverage_metric():
    r = coverage("hay un servicio ftp en el puerto 21", ["ftp", "21", "ssh"])
    assert r["covered"] == 2
    assert r["expected"] == 3
    assert 0.6 < r["coverage"] < 0.7


def test_extract_and_unsupported_cves():
    assert extract_cves("CVE-2011-2523 y CVE-2020-0001") == {"CVE-2011-2523", "CVE-2020-0001"}
    assert unsupported_cves("aparece CVE-9999-0001", {"CVE-2011-2523"}) == {"CVE-9999-0001"}


def test_prioritization_order():
    scan = ScanResult(source_tool="test", hosts=[Host(address="h", services=[
        Service(port=1, protocol="tcp", state="open", service="a",
                vulnerabilities=[CVE(id="CVE-1", cvss=3.0, severity="LOW")]),
        Service(port=2, protocol="tcp", state="open", service="b",
                vulnerabilities=[CVE(id="CVE-2", cvss=9.8, severity="CRITICAL")]),
    ])])
    findings = prioritized_findings(scan)
    assert findings[0].cve.id == "CVE-2"  # el más crítico primero


def test_attack_owasp_context():
    scan = ScanResult(source_tool="test", hosts=[Host(address="h", services=[
        Service(port=445, protocol="tcp", state="open", service="microsoft-ds")])])
    ctx = attack_owasp_context(scan)
    assert "ATT&CK" in ctx and "T1021.002" in ctx
