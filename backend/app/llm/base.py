from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Abstract interface for LLM providers."""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Return a completion for the given prompt."""
