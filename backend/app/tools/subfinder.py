from __future__ import annotations

from app.tools.base import BaseTool


class SubfinderTool(BaseTool):
    name = "subfinder"

    def run(self, domain: str, **kwargs) -> str:
        return self._exec(["subfinder", "-d", domain, "-silent"])
