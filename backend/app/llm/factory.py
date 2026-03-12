"""Factory for creating LLM provider instances from application settings."""

import logging

from backend.app.core.config import settings
from backend.app.llm.base import LLMProvider
from backend.app.llm.null_provider import NullLLMProvider

logger = logging.getLogger(__name__)


def build_llm_provider() -> LLMProvider:
    """Instantiate and return the configured LLM provider.

    The provider is selected by the ``LLM_PROVIDER`` environment variable
    (or the ``llm_provider`` field in ``.env``).  Falls back to
    ``NullLLMProvider`` if the provider name is unrecognised or a required
    dependency / credential is missing.

    Returns:
        A concrete :class:`~backend.app.llm.base.LLMProvider` instance.
    """
    provider_name = settings.llm_provider.lower().strip()

    if provider_name in ("null", ""):
        return NullLLMProvider()

    if provider_name == "ollama":
        from backend.app.llm.ollama_provider import OllamaProvider
        return OllamaProvider(
            host=settings.ollama_host,
            model=settings.ollama_model,
            embed_model=settings.ollama_embed_model,
        )

    if provider_name == "openai":
        if not settings.openai_api_key:
            logger.warning(
                "LLM_PROVIDER=openai but OPENAI_API_KEY is not set. "
                "Falling back to NullLLMProvider."
            )
            return NullLLMProvider()
        try:
            from backend.app.llm.openai_provider import OpenAIProvider
            return OpenAIProvider(
                api_key=settings.openai_api_key,
                model=settings.openai_model,
                embed_model=settings.openai_embed_model,
            )
        except ImportError:
            logger.warning(
                "LLM_PROVIDER=openai but 'openai' package is not installed. "
                "Run: pip install openai. Falling back to NullLLMProvider."
            )
            return NullLLMProvider()

    if provider_name == "anthropic":
        if not settings.anthropic_api_key:
            logger.warning(
                "LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set. "
                "Falling back to NullLLMProvider."
            )
            return NullLLMProvider()
        try:
            from backend.app.llm.anthropic_provider import AnthropicProvider
            return AnthropicProvider(
                api_key=settings.anthropic_api_key,
                model=settings.anthropic_model,
            )
        except ImportError:
            logger.warning(
                "LLM_PROVIDER=anthropic but 'anthropic' package is not installed. "
                "Run: pip install anthropic. Falling back to NullLLMProvider."
            )
            return NullLLMProvider()

    logger.warning(
        "Unknown LLM_PROVIDER=%r. Valid values: null, ollama, openai, anthropic. "
        "Falling back to NullLLMProvider.",
        provider_name,
    )
    return NullLLMProvider()
