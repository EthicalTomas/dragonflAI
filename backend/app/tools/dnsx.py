from __future__ import annotations

from app.tools.base import BaseTool


class DnsxTool(BaseTool):
    name = "dnsx"

    def run(self, domain: str, **kwargs) -> str:
        return self._exec(["dnsx", "-d", domain, "-resp", "-silent"])
