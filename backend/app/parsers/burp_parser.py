from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_burp(xml_output: str) -> list[dict]:
    """Return a list of issue records from a Burp Suite XML export."""
    results = []
    root = ET.fromstring(xml_output)
    for issue in root.findall("issue"):
        name_el = issue.find("name")
        host_el = issue.find("host")
        path_el = issue.find("path")
        severity_el = issue.find("severity")
        results.append(
            {
                "name": name_el.text if name_el is not None else "",
                "host": host_el.text if host_el is not None else "",
                "path": path_el.text if path_el is not None else "",
                "severity": severity_el.text if severity_el is not None else "",
            }
        )
    return results
