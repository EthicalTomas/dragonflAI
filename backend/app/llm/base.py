import abc


class LLMProvider(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Return the provider name (e.g. 'null', 'ollama', 'openai')."""

    @abc.abstractmethod
    def generate(self, prompt: str, context: str = "", max_tokens: int = 1024) -> str:
        """Generate text from a prompt.

        Args:
            prompt: The input prompt string.
            context: Optional context string.
            max_tokens: Maximum number of tokens to generate.

        Returns:
            The generated text string.
        """

    @abc.abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """Produce embedding vectors for the given texts.

        Args:
            texts: A list of text strings to embed.

        Returns:
            A list of embedding vectors (each a list of floats).
        """
