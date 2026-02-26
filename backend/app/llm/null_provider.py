from backend.app.llm.base import LLMProvider


class NullLLMProvider(LLMProvider):
    @property
    def name(self) -> str:
        return "null"

    def generate(self, prompt: str, context: str = "", max_tokens: int = 1024) -> str:
        return "[LLM disabled] No language model is configured. Upgrade to an LLM provider to enable AI features."

    def embed(self, texts: list[str]) -> list[list[float]]:
        return []
