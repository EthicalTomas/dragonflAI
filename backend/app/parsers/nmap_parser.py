from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_nmap(xml_output: str) -> list[dict]:
    """Return a list of host/port records from nmap XML output."""
    results = []
    root = ET.fromstring(xml_output)
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""
        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            results.append(
                {
                    "host": addr,
                    "port": port_el.get("portid"),
                    "protocol": port_el.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else "",
                }
            )
    return results
