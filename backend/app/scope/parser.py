from __future__ import annotations


def parse_scope(scope_raw: str) -> list[str]:
    """Parse raw scope text into a list of scope rules (one per non-empty line)."""
    lines = []
    for line in scope_raw.splitlines():
        rule = line.strip()
        if rule and not rule.startswith("#"):
            lines.append(rule)
    return lines
