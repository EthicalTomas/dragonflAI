import base64
import binascii
import logging
import os
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


def _decode_field(element: ET.Element | None) -> str:
    if element is None:
        return ""
    raw = element.text or ""
    if element.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            return raw
    return raw


def parse_burp_xml(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        logger.warning("Burp XML file not found: %s", filepath)
        return []

    results: list[dict] = []

    try:
        context = ET.iterparse(filepath, events=("end",))
        for event, elem in context:
            if elem.tag != "item":
                continue

            url = (elem.findtext("url") or "").strip()
            host = (elem.findtext("host") or "").strip()
            port_text = (elem.findtext("port") or "0").strip()
            try:
                port = int(port_text)
            except ValueError:
                port = 0
            protocol = (elem.findtext("protocol") or "").strip()
            method = (elem.findtext("method") or "").strip()
            path = (elem.findtext("path") or "").strip()
            status_text = (elem.findtext("status") or "0").strip()
            try:
                status = int(status_text)
            except ValueError:
                status = 0
            request = _decode_field(elem.find("request"))
            response = _decode_field(elem.find("response"))

            results.append({
                "url": url,
                "host": host,
                "port": port,
                "protocol": protocol,
                "method": method,
                "path": path,
                "status": status,
                "request": request,
                "response": response,
            })

            elem.clear()
    except ET.ParseError as exc:
        logger.warning("Failed to parse Burp XML file %s: %s", filepath, exc)
        return []
    except OSError as exc:
        logger.warning("Failed to read Burp XML file %s: %s", filepath, exc)
        return []

    return results
