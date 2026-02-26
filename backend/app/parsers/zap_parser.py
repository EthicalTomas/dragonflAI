import json
import logging
import os
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

def parse_zap_json(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        logger.warning("ZAP JSON file not found: %s", filepath)
        return []

    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to parse ZAP JSON file %s: %s", filepath, exc)
        return []

    results: list[dict] = []
    alerts = data if isinstance(data, list) else data.get("alerts", [])
    for alert in alerts:
        instances = alert.get("instances") or [{}]
        for instance in instances:
            results.append({
                "name": alert.get("name", ""),
                "risk": alert.get("riskdesc", alert.get("risk", "")),
                "confidence": alert.get("confidence", ""),
                "description": alert.get("desc", alert.get("description", "")),
                "url": instance.get("uri", alert.get("url", "")),
                "method": instance.get("method", alert.get("method", "")),
                "param": instance.get("param", alert.get("param", "")),
                "evidence": instance.get("evidence", alert.get("evidence", "")),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
            })

    return results


def parse_zap_xml(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        logger.warning("ZAP XML file not found: %s", filepath)
        return []

    try:
        tree = ET.parse(filepath)
    except ET.ParseError as exc:
        logger.warning("Failed to parse ZAP XML file %s: %s", filepath, exc)
        return []
    except OSError as exc:
        logger.warning("Failed to read ZAP XML file %s: %s", filepath, exc)
        return []

    root = tree.getroot()
    results: list[dict] = []

    for item in root.iter("alertitem"):
        results.append({
            "name": (item.findtext("alert") or item.findtext("name") or ""),
            "risk": (item.findtext("riskdesc") or item.findtext("risk") or ""),
            "confidence": (item.findtext("confidence") or ""),
            "description": (item.findtext("desc") or item.findtext("description") or ""),
            "url": (item.findtext("uri") or item.findtext("url") or ""),
            "method": (item.findtext("method") or ""),
            "param": (item.findtext("param") or ""),
            "evidence": (item.findtext("evidence") or ""),
            "solution": (item.findtext("solution") or ""),
            "reference": (item.findtext("reference") or ""),
        })

    return results
