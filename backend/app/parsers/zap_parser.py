from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_zap(xml_output: str) -> list[dict]:
    """Return a list of alert records from a ZAP XML export."""
    results = []
    root = ET.fromstring(xml_output)
    for alert in root.findall(".//alertitem"):
        name_el = alert.find("alert")
        risk_el = alert.find("riskdesc")
        uri_el = alert.find("uri")
        results.append(
            {
                "name": name_el.text if name_el is not None else "",
                "risk": risk_el.text if risk_el is not None else "",
                "uri": uri_el.text if uri_el is not None else "",
            }
        )
    return results
