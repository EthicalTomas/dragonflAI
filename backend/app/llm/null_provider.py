from __future__ import annotations

from app.llm.base import LLMProvider


class NullLLMProvider(LLMProvider):
    """Stub provider — returns a fixed message when no LLM is configured."""

    def complete(self, prompt: str) -> str:
        return "LLM disabled"
