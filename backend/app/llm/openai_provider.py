import logging

from backend.app.llm.base import LLMProvider

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_EMBED_MODEL = "text-embedding-3-small"


class OpenAIProvider(LLMProvider):
    """LLM provider backed by the OpenAI API.

    Requires the ``openai`` package (``pip install openai``) and a valid API
    key set via the ``OPENAI_API_KEY`` environment variable or passed directly.

    Environment variables (via Settings):
        OPENAI_API_KEY   – your OpenAI secret key
        OPENAI_MODEL     – chat model (default: gpt-4o-mini)
        OPENAI_EMBED_MODEL – embedding model (default: text-embedding-3-small)
    """

    def __init__(
        self,
        api_key: str,
        model: str = _DEFAULT_MODEL,
        embed_model: str = _DEFAULT_EMBED_MODEL,
    ) -> None:
        try:
            from openai import OpenAI  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for OpenAIProvider. "
                "Install it with: pip install openai"
            ) from exc

        self._client = OpenAI(api_key=api_key)
        self._model = model
        self._embed_model = embed_model

    @property
    def name(self) -> str:
        return "openai"

    def generate(self, prompt: str, context: str = "", max_tokens: int = 1024) -> str:
        messages = []
        if context:
            messages.append({"role": "system", "content": context})
        messages.append({"role": "user", "content": prompt})

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception:
            logger.error("OpenAI API call failed.", exc_info=True)
            raise

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        try:
            response = self._client.embeddings.create(
                model=self._embed_model,
                input=texts,
            )
            return [item.embedding for item in response.data]
        except Exception:
            logger.error("OpenAI embedding call failed.", exc_info=True)
            raise
