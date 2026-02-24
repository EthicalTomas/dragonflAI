from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod


class BaseTool(ABC):
    """Abstract base class for external tool wrappers."""

    name: str = ""

    @abstractmethod
    def run(self, *args: str, **kwargs) -> str:
        """Execute the tool and return its raw output."""

    def _exec(self, cmd: list[str], timeout: int = 300) -> str:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result.check_returncode()
        return result.stdout
