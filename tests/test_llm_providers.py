"""Tests for LLM provider implementations and the provider factory.

These tests verify the behaviour of the new LLM providers without
requiring a live database, running Ollama instance, or real API keys.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch


class TestNullLLMProvider(unittest.TestCase):
    def test_name_is_null(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = NullLLMProvider()
        self.assertEqual(provider.name, "null")

    def test_generate_returns_disabled_message(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = NullLLMProvider()
        result = provider.generate("hello")
        self.assertIn("LLM disabled", result)

    def test_embed_returns_empty_list(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = NullLLMProvider()
        result = provider.embed(["hello", "world"])
        self.assertEqual(result, [])


class TestOllamaProvider(unittest.TestCase):
    """OllamaProvider tests using mocked httpx responses."""

    def _make_provider(self):
        from backend.app.llm.ollama_provider import OllamaProvider

        return OllamaProvider(host="http://localhost:11434", model="llama3")

    def test_name_is_ollama(self) -> None:
        provider = self._make_provider()
        self.assertEqual(provider.name, "ollama")

    def test_generate_calls_ollama_api(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": "test output"}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            provider = self._make_provider()
            result = provider.generate("test prompt")

        self.assertEqual(result, "test output")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        self.assertIn("/api/chat", call_kwargs[0][0])

    def test_generate_with_context_adds_system_message(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": "reply"}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            provider = self._make_provider()
            provider.generate("prompt", context="system context")

        payload = mock_post.call_args[1]["json"]
        messages = payload["messages"]
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "system context")
        self.assertEqual(messages[1]["role"], "user")

    def test_generate_raises_on_connection_error(self) -> None:
        import httpx

        with patch("httpx.post", side_effect=httpx.RequestError("refused")):
            provider = self._make_provider()
            with self.assertRaises(RuntimeError) as ctx:
                provider.generate("prompt")
        self.assertIn("Ollama", str(ctx.exception))

    def test_embed_returns_vectors(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"embedding": [0.1, 0.2, 0.3]}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response):
            provider = self._make_provider()
            result = provider.embed(["hello"])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], [0.1, 0.2, 0.3])


class TestOpenAIProvider(unittest.TestCase):
    """OpenAIProvider tests using a mocked openai client."""

    def _make_provider_with_mock_client(self):
        mock_openai_module = MagicMock()
        mock_client = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client

        with patch.dict(sys.modules, {"openai": mock_openai_module}):
            # Re-import to pick up the mocked module
            if "backend.app.llm.openai_provider" in sys.modules:
                del sys.modules["backend.app.llm.openai_provider"]
            from backend.app.llm.openai_provider import OpenAIProvider
            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o-mini")
            provider._client = mock_client
        return provider, mock_client

    def test_name_is_openai(self) -> None:
        provider, _ = self._make_provider_with_mock_client()
        self.assertEqual(provider.name, "openai")

    def test_generate_calls_chat_completions(self) -> None:
        provider, mock_client = self._make_provider_with_mock_client()
        mock_choice = MagicMock()
        mock_choice.message.content = "generated text"
        mock_client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )

        result = provider.generate("test prompt")
        self.assertEqual(result, "generated text")
        mock_client.chat.completions.create.assert_called_once()

    def test_embed_returns_vectors(self) -> None:
        provider, mock_client = self._make_provider_with_mock_client()
        mock_item = MagicMock()
        mock_item.embedding = [0.5, 0.6]
        mock_client.embeddings.create.return_value = MagicMock(data=[mock_item])

        result = provider.embed(["text"])
        self.assertEqual(result, [[0.5, 0.6]])

    def test_embed_empty_list_returns_empty(self) -> None:
        provider, mock_client = self._make_provider_with_mock_client()
        result = provider.embed([])
        self.assertEqual(result, [])
        mock_client.embeddings.create.assert_not_called()

    def test_missing_openai_package_raises_import_error(self) -> None:
        with patch.dict(sys.modules, {"openai": None}):
            if "backend.app.llm.openai_provider" in sys.modules:
                del sys.modules["backend.app.llm.openai_provider"]
            from backend.app.llm.openai_provider import OpenAIProvider
            with self.assertRaises(ImportError) as ctx:
                OpenAIProvider(api_key="sk-test")
        self.assertIn("openai", str(ctx.exception))


class TestAnthropicProvider(unittest.TestCase):
    """AnthropicProvider tests using a mocked anthropic client."""

    def _make_provider_with_mock_client(self):
        mock_anthropic_module = MagicMock()
        mock_client = MagicMock()
        mock_anthropic_module.Anthropic.return_value = mock_client

        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            if "backend.app.llm.anthropic_provider" in sys.modules:
                del sys.modules["backend.app.llm.anthropic_provider"]
            from backend.app.llm.anthropic_provider import AnthropicProvider
            provider = AnthropicProvider(
                api_key="sk-ant-test", model="claude-3-5-haiku-latest"
            )
            provider._client = mock_client
        return provider, mock_client

    def test_name_is_anthropic(self) -> None:
        provider, _ = self._make_provider_with_mock_client()
        self.assertEqual(provider.name, "anthropic")

    def test_generate_calls_messages_create(self) -> None:
        provider, mock_client = self._make_provider_with_mock_client()
        mock_content = MagicMock()
        mock_content.text = "claude says hi"
        mock_client.messages.create.return_value = MagicMock(content=[mock_content])

        result = provider.generate("prompt")
        self.assertEqual(result, "claude says hi")

    def test_embed_raises_not_implemented(self) -> None:
        provider, _ = self._make_provider_with_mock_client()
        with self.assertRaises(NotImplementedError):
            provider.embed(["text"])

    def test_missing_anthropic_package_raises_import_error(self) -> None:
        with patch.dict(sys.modules, {"anthropic": None}):
            if "backend.app.llm.anthropic_provider" in sys.modules:
                del sys.modules["backend.app.llm.anthropic_provider"]
            from backend.app.llm.anthropic_provider import AnthropicProvider
            with self.assertRaises(ImportError) as ctx:
                AnthropicProvider(api_key="sk-ant-test")
        self.assertIn("anthropic", str(ctx.exception))


class TestLLMFactory(unittest.TestCase):
    """Tests for build_llm_provider() factory function.

    The factory imports backend.app.core.config.settings which requires
    DATABASE_URL and REDIS_URL.  We set those via env vars and then mock
    only the LLM-related fields on the settings object.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure Settings can be instantiated by providing required env vars."""
        import os
        os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")
        os.environ.setdefault("REDIS_URL", "redis://localhost/0")

    def _run_factory(self, env_overrides: dict):
        """Run build_llm_provider with a fully mocked settings object."""
        settings_mock = MagicMock()
        settings_mock.llm_provider = env_overrides.get("llm_provider", "null")
        settings_mock.ollama_host = env_overrides.get("ollama_host", "http://localhost:11434")
        settings_mock.ollama_model = env_overrides.get("ollama_model", "llama3")
        settings_mock.ollama_embed_model = env_overrides.get("ollama_embed_model", "nomic-embed-text")
        settings_mock.openai_api_key = env_overrides.get("openai_api_key", "")
        settings_mock.openai_model = env_overrides.get("openai_model", "gpt-4o-mini")
        settings_mock.openai_embed_model = env_overrides.get("openai_embed_model", "text-embedding-3-small")
        settings_mock.anthropic_api_key = env_overrides.get("anthropic_api_key", "")
        settings_mock.anthropic_model = env_overrides.get("anthropic_model", "claude-3-5-haiku-latest")

        # Remove cached factory so it re-imports fresh each time
        sys.modules.pop("backend.app.llm.factory", None)

        from backend.app.llm import factory as factory_module
        with patch.object(factory_module, "settings", settings_mock):
            return factory_module.build_llm_provider()

    def test_null_returns_null_provider(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = self._run_factory({"llm_provider": "null"})
        self.assertIsInstance(provider, NullLLMProvider)

    def test_empty_string_returns_null_provider(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = self._run_factory({"llm_provider": ""})
        self.assertIsInstance(provider, NullLLMProvider)

    def test_unknown_provider_falls_back_to_null(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = self._run_factory({"llm_provider": "some_unknown"})
        self.assertIsInstance(provider, NullLLMProvider)

    def test_ollama_returns_ollama_provider(self) -> None:
        from backend.app.llm.ollama_provider import OllamaProvider

        provider = self._run_factory({"llm_provider": "ollama"})
        self.assertIsInstance(provider, OllamaProvider)

    def test_openai_without_key_falls_back_to_null(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = self._run_factory({"llm_provider": "openai", "openai_api_key": ""})
        self.assertIsInstance(provider, NullLLMProvider)

    def test_openai_with_key_returns_openai_provider(self) -> None:
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = MagicMock()

        sys.modules.pop("backend.app.llm.openai_provider", None)

        with patch.dict(sys.modules, {"openai": mock_openai_module}):
            from backend.app.llm.openai_provider import OpenAIProvider

            provider = self._run_factory(
                {"llm_provider": "openai", "openai_api_key": "sk-real-key"}
            )
            self.assertIsInstance(provider, OpenAIProvider)

    def test_anthropic_without_key_falls_back_to_null(self) -> None:
        from backend.app.llm.null_provider import NullLLMProvider

        provider = self._run_factory(
            {"llm_provider": "anthropic", "anthropic_api_key": ""}
        )
        self.assertIsInstance(provider, NullLLMProvider)

    def test_anthropic_with_key_returns_anthropic_provider(self) -> None:
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.Anthropic.return_value = MagicMock()

        sys.modules.pop("backend.app.llm.anthropic_provider", None)

        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from backend.app.llm.anthropic_provider import AnthropicProvider

            provider = self._run_factory(
                {"llm_provider": "anthropic", "anthropic_api_key": "sk-ant-real"}
            )
            self.assertIsInstance(provider, AnthropicProvider)


if __name__ == "__main__":
    unittest.main()
