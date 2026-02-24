from __future__ import annotations

from app.tools.base import BaseTool


class HttpxProbeTool(BaseTool):
    name = "httpx"

    def run(self, target: str, **kwargs) -> str:
        return self._exec(["httpx", "-u", target, "-json", "-silent"])
