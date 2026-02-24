from __future__ import annotations


def parse_subfinder(output: str) -> list[str]:
    """Return a list of subdomains from subfinder plain-text output."""
    return [line.strip() for line in output.splitlines() if line.strip()]
