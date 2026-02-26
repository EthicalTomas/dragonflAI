import json
import logging
import os

logger = logging.getLogger(__name__)


def parse_httpx_output(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        logger.warning("httpx output file not found: %s", filepath)
        return []

    results: list[dict] = []

    try:
        with open(filepath, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Failed to parse httpx JSON line: %s | error: %s", line, exc)
                    continue
                results.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", 0),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                    "host": data.get("host", ""),
                    "content_length": data.get("content_length", 0),
                })
    except OSError as exc:
        logger.warning("Failed to read httpx output file %s: %s", filepath, exc)
        return []

    return results
