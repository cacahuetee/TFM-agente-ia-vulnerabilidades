"""Parser de la salida XML de Nmap (nmap -oX) al esquema normalizado."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from src.schema import ScanResult, Host, Service


def parse_nmap_xml(path: str) -> ScanResult:
    return _parse_root(ET.parse(path).getroot())


def parse_nmap_string(xml_text: str) -> ScanResult:
    return _parse_root(ET.fromstring(xml_text))


def _parse_root(root: ET.Element) -> ScanResult:
    result = ScanResult(source_tool="nmap", command=root.get("args"))
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        address = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                address = addr_el.get("addr")
                break
        if address is None:
            addr_el = host_el.find("address")
            address = addr_el.get("addr") if addr_el is not None else "desconocido"

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        host = Host(address=address, hostname=hostname, state=state)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                port_state = state_el.get("state") if state_el is not None else "unknown"
                svc_el = port_el.find("service")
                service = product = version = None
                cpe_list: list[str] = []
                if svc_el is not None:
                    service = svc_el.get("name")
                    product = svc_el.get("product")
                    version = svc_el.get("version")
                    cpe_list = [c.text for c in svc_el.findall("cpe") if c.text]
                host.services.append(Service(
                    port=int(port_el.get("portid")),
                    protocol=port_el.get("protocol"),
                    state=port_state,
                    service=service, product=product, version=version, cpe=cpe_list,
                ))
        result.hosts.append(host)
    return result
