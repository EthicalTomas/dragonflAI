from __future__ import annotations

import json


def parse_httpx(output: str) -> list[dict]:
    """Return a list of parsed httpx JSON records."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results
