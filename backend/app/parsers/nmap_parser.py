import logging
import os
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


def parse_nmap_output(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        logger.warning("nmap output file not found: %s", filepath)
        return []

    try:
        tree = ET.parse(filepath)
    except ET.ParseError as exc:
        logger.warning("Failed to parse nmap XML file %s: %s", filepath, exc)
        return []
    except OSError as exc:
        logger.warning("Failed to read nmap output file %s: %s", filepath, exc)
        return []

    root = tree.getroot()
    results: list[dict] = []

    for host in root.findall("host"):
        address_el = host.find("address[@addrtype='ipv4']")
        if address_el is None:
            address_el = host.find("address")
        if address_el is None:
            continue
        ip = address_el.get("addr", "")

        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hostname_el = hostnames_el.find("hostname")
            if hostname_el is not None:
                hostname = hostname_el.get("name", "")

        ports: list[dict] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                service_name = ""
                service_version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    service_version = f"{product} {version}".strip()
                portid = port_el.get("portid")
                if portid is None:
                    continue
                ports.append({
                    "port": int(portid),
                    "protocol": port_el.get("protocol", ""),
                    "state": state_el.get("state", ""),
                    "service": service_name,
                    "version": service_version,
                })

        results.append({
            "ip": ip,
            "hostname": hostname,
            "ports": ports,
        })

    return results
