import logging

import httpx

from backend.app.llm.base import LLMProvider

logger = logging.getLogger(__name__)

_DEFAULT_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "llama3"
_DEFAULT_EMBED_MODEL = "nomic-embed-text"
_DEFAULT_TIMEOUT = 120.0


class OllamaProvider(LLMProvider):
    """LLM provider backed by a local Ollama instance.

    Requires Ollama to be running (https://ollama.com).  No API key is needed.
    All inference runs on-device — no data leaves the machine.

    Environment variables (via Settings):
        OLLAMA_HOST  – base URL of the Ollama server (default: http://localhost:11434)
        OLLAMA_MODEL – chat model to use (default: llama3)
        OLLAMA_EMBED_MODEL – embedding model (default: nomic-embed-text)
    """

    def __init__(
        self,
        host: str = _DEFAULT_HOST,
        model: str = _DEFAULT_MODEL,
        embed_model: str = _DEFAULT_EMBED_MODEL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._host = host.rstrip("/")
        self._model = model
        self._embed_model = embed_model
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "ollama"

    def generate(self, prompt: str, context: str = "", max_tokens: int = 1024) -> str:
        messages = []
        if context:
            messages.append({"role": "system", "content": context})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }

        try:
            response = httpx.post(
                f"{self._host}/api/chat",
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data["message"]["content"]
        except httpx.HTTPStatusError as exc:
            logger.error("Ollama API error: %s %s", exc.response.status_code, exc.response.text)
            raise
        except httpx.RequestError as exc:
            logger.error("Ollama connection error: %s", exc)
            raise RuntimeError(
                f"Could not connect to Ollama at {self._host}. "
                "Ensure Ollama is running: https://ollama.com"
            ) from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        embeddings: list[list[float]] = []
        for text in texts:
            payload = {"model": self._embed_model, "prompt": text}
            try:
                response = httpx.post(
                    f"{self._host}/api/embeddings",
                    json=payload,
                    timeout=self._timeout,
                )
                response.raise_for_status()
                data = response.json()
                embeddings.append(data["embedding"])
            except httpx.HTTPStatusError as exc:
                logger.error(
                    "Ollama embedding error: %s %s",
                    exc.response.status_code,
                    exc.response.text,
                )
                raise
            except httpx.RequestError as exc:
                logger.error("Ollama connection error (embed): %s", exc)
                raise RuntimeError(
                    f"Could not connect to Ollama at {self._host}."
                ) from exc
        return embeddings
