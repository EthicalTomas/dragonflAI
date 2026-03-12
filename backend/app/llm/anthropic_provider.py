import logging

from backend.app.llm.base import LLMProvider

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "claude-3-5-haiku-latest"
_DEFAULT_MAX_TOKENS = 1024


class AnthropicProvider(LLMProvider):
    """LLM provider backed by the Anthropic API (Claude models).

    Requires the ``anthropic`` package (``pip install anthropic``) and a valid
    API key set via the ``ANTHROPIC_API_KEY`` environment variable or passed
    directly.

    Note: Anthropic does not currently offer a public embedding API.  The
    ``embed`` method raises ``NotImplementedError``; use ``OllamaProvider`` or
    ``OpenAIProvider`` for embeddings when using Anthropic for generation.

    Environment variables (via Settings):
        ANTHROPIC_API_KEY – your Anthropic secret key
        ANTHROPIC_MODEL   – Claude model to use (default: claude-3-5-haiku-latest)
    """

    def __init__(
        self,
        api_key: str,
        model: str = _DEFAULT_MODEL,
    ) -> None:
        try:
            import anthropic  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for AnthropicProvider. "
                "Install it with: pip install anthropic"
            ) from exc

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    @property
    def name(self) -> str:
        return "anthropic"

    def generate(self, prompt: str, context: str = "", max_tokens: int = _DEFAULT_MAX_TOKENS) -> str:
        system = context if context else "You are a helpful security research assistant."

        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception:
            logger.error("Anthropic API call failed.", exc_info=True)
            raise

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError(
            "Anthropic does not provide a public embeddings API. "
            "Use OllamaProvider or OpenAIProvider for embeddings."
        )
