from __future__ import annotations

from app.tools.base import BaseTool


class NmapTool(BaseTool):
    name = "nmap"

    def run(self, target: str, **kwargs) -> str:
        return self._exec(["nmap", "-oX", "-", target])
