"""Unit tests for verification methods.

Tests cover:
- HttpReplayVerifier: success (confirmed/unconfirmed), network failure
- DnsRecheckVerifier: success, failure, expected IP matching
- ScreenshotVerifier: disabled by default, returns inconclusive
- Scope enforcement via ScopeValidator
- HttpReplayVerifier response body redaction and size limits
"""

import socket
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers to isolate the verify package from heavy dependencies
# ---------------------------------------------------------------------------

def _build_mock(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


# We need httpx available; if not installed use a stub
try:
    import httpx as _httpx_real  # noqa: F401
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


class TestHttpReplayVerifier(unittest.TestCase):
    """Tests for HttpReplayVerifier."""

    def setUp(self) -> None:
        # Ensure the verify package is importable
        import importlib
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "backend.app.verify.base",
            "backend/app/verify/base.py",
        )
        base_mod = importlib.util.module_from_spec(spec)
        sys.modules["backend.app.verify.base"] = base_mod
        spec.loader.exec_module(base_mod)

        if _HTTPX_AVAILABLE:
            spec2 = importlib.util.spec_from_file_location(
                "backend.app.verify.http_replay",
                "backend/app/verify/http_replay.py",
            )
            replay_mod = importlib.util.module_from_spec(spec2)
            sys.modules["backend.app.verify.http_replay"] = replay_mod
            spec2.loader.exec_module(replay_mod)
            self.HttpReplayVerifier = replay_mod.HttpReplayVerifier
            self.TransportError = _httpx_real.TransportError
        else:
            self.skipTest("httpx not available")

    def test_confirmed_when_marker_found(self) -> None:
        """status=confirmed when a marker is present in the response body."""
        verifier = self.HttpReplayVerifier(markers=["SECRET_TOKEN"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "http://example.com/"
        mock_response.content = b"Hello SECRET_TOKEN world"
        mock_response.headers = {}

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "confirmed")
        self.assertIn("SECRET_TOKEN", result.evidence.get("markers_matched", []))

    def test_unconfirmed_when_marker_absent(self) -> None:
        """status=unconfirmed when markers are specified but not present."""
        verifier = self.HttpReplayVerifier(markers=["MISSING_MARKER"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "http://example.com/"
        mock_response.content = b"Normal response body"
        mock_response.headers = {}

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "unconfirmed")

    def test_inconclusive_on_transport_error(self) -> None:
        """status=inconclusive when a network error occurs."""
        verifier = self.HttpReplayVerifier()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = _httpx_real.ConnectError("connection refused")
            mock_client_cls.return_value = mock_client

            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("error", result.evidence)

    def test_authorization_header_redacted(self) -> None:
        """Authorization header must not appear in captured evidence."""
        verifier = self.HttpReplayVerifier()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "http://example.com/"
        mock_response.content = b"body"
        mock_response.headers = {
            "authorization": "Bearer secret_token_xyz",
            "content-type": "text/html",
        }

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = verifier.verify("http://example.com/")

        resp_headers = result.evidence.get("response_headers", {})
        self.assertNotIn("Bearer secret_token_xyz", str(resp_headers))
        self.assertEqual(resp_headers.get("authorization"), "[REDACTED]")

    def test_body_truncated_to_max_size(self) -> None:
        """Response body capture must be limited to _MAX_BODY_BYTES."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "backend.app.verify.http_replay",
            "backend/app/verify/http_replay.py",
        )
        replay_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay_mod)

        max_bytes = replay_mod._MAX_BODY_BYTES
        large_body = b"A" * (max_bytes + 500)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "http://example.com/"
        mock_response.content = large_body
        mock_response.headers = {}

        verifier = replay_mod.HttpReplayVerifier()
        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = verifier.verify("http://example.com/")

        snippet = result.evidence.get("body_snippet", "")
        # snippet is at most 2000 chars, but the raw body capture is bounded
        self.assertLessEqual(len(snippet.encode()), max_bytes + 1)

    def test_server_error_gives_unconfirmed_without_markers(self) -> None:
        """5xx responses without markers return unconfirmed."""
        verifier = self.HttpReplayVerifier()

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.url = "http://example.com/"
        mock_response.content = b"Internal Server Error"
        mock_response.headers = {}

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "unconfirmed")


class TestDnsRecheckVerifier(unittest.TestCase):
    """Tests for DnsRecheckVerifier."""

    def _load_verifier(self):
        import importlib.util

        for mod_name in ["backend.app.verify.base", "backend.app.verify.dns_recheck"]:
            sys.modules.pop(mod_name, None)

        spec = importlib.util.spec_from_file_location(
            "backend.app.verify.base",
            "backend/app/verify/base.py",
        )
        base_mod = importlib.util.module_from_spec(spec)
        sys.modules["backend.app.verify.base"] = base_mod
        spec.loader.exec_module(base_mod)

        spec2 = importlib.util.spec_from_file_location(
            "backend.app.verify.dns_recheck",
            "backend/app/verify/dns_recheck.py",
        )
        dns_mod = importlib.util.module_from_spec(spec2)
        sys.modules["backend.app.verify.dns_recheck"] = dns_mod
        spec2.loader.exec_module(dns_mod)
        return dns_mod.DnsRecheckVerifier

    def test_confirmed_when_no_expectations(self) -> None:
        """Without expected_ips, a successful DNS lookup gives confirmed."""
        DnsRecheckVerifier = self._load_verifier()
        verifier = DnsRecheckVerifier()

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 0))
            ]
            result = verifier.verify("example.com")

        self.assertEqual(result.status, "confirmed")
        self.assertIn("93.184.216.34", result.evidence["resolved_ips"])

    def test_confirmed_when_expected_ip_matches(self) -> None:
        """status=confirmed when expected_ips list contains a resolved IP."""
        DnsRecheckVerifier = self._load_verifier()
        verifier = DnsRecheckVerifier(expected_ips=["93.184.216.34"])

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 0))
            ]
            result = verifier.verify("example.com")

        self.assertEqual(result.status, "confirmed")

    def test_unconfirmed_when_expected_ip_not_resolved(self) -> None:
        """status=unconfirmed when expected IPs are set but not resolved."""
        DnsRecheckVerifier = self._load_verifier()
        verifier = DnsRecheckVerifier(expected_ips=["1.2.3.4"])

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 0))
            ]
            result = verifier.verify("example.com")

        self.assertEqual(result.status, "unconfirmed")

    def test_inconclusive_on_dns_failure(self) -> None:
        """status=inconclusive when DNS resolution raises gaierror."""
        DnsRecheckVerifier = self._load_verifier()
        verifier = DnsRecheckVerifier()

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            result = verifier.verify("nonexistent.invalid")

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("error", result.evidence)


class TestScreenshotVerifier(unittest.TestCase):
    """Tests for ScreenshotVerifier."""

    def _load_verifier(self):
        import importlib.util

        for mod_name in ["backend.app.verify.base", "backend.app.verify.screenshot"]:
            sys.modules.pop(mod_name, None)

        spec = importlib.util.spec_from_file_location(
            "backend.app.verify.base",
            "backend/app/verify/base.py",
        )
        base_mod = importlib.util.module_from_spec(spec)
        sys.modules["backend.app.verify.base"] = base_mod
        spec.loader.exec_module(base_mod)

        spec2 = importlib.util.spec_from_file_location(
            "backend.app.verify.screenshot",
            "backend/app/verify/screenshot.py",
        )
        ss_mod = importlib.util.module_from_spec(spec2)
        sys.modules["backend.app.verify.screenshot"] = ss_mod
        spec2.loader.exec_module(ss_mod)
        return ss_mod.ScreenshotVerifier

    def test_inconclusive_when_disabled(self) -> None:
        """ScreenshotVerifier returns inconclusive when not explicitly enabled."""
        ScreenshotVerifier = self._load_verifier()
        verifier = ScreenshotVerifier(enabled=False)
        result = verifier.verify("http://example.com/")
        self.assertEqual(result.status, "inconclusive")
        self.assertIn("disabled", result.notes.lower())

    def test_inconclusive_when_playwright_missing(self) -> None:
        """ScreenshotVerifier returns inconclusive when playwright is not installed."""
        ScreenshotVerifier = self._load_verifier()
        verifier = ScreenshotVerifier(enabled=True)

        # Make playwright import fail
        with patch.dict(sys.modules, {"playwright": None, "playwright.sync_api": None}):
            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "inconclusive")

    def test_inconclusive_on_navigation_failure(self) -> None:
        """ScreenshotVerifier returns inconclusive on Playwright navigation error."""
        ScreenshotVerifier = self._load_verifier()
        verifier = ScreenshotVerifier(enabled=True)

        mock_page = MagicMock()
        mock_page.goto.side_effect = RuntimeError("navigation timeout")
        mock_browser = MagicMock()
        mock_browser.new_page.return_value = mock_page
        mock_pw_ctx = MagicMock()
        mock_pw_ctx.chromium.launch.return_value = mock_browser

        mock_sync_playwright = MagicMock()
        mock_sync_playwright.return_value.__enter__ = MagicMock(return_value=mock_pw_ctx)
        mock_sync_playwright.return_value.__exit__ = MagicMock(return_value=False)

        mock_sync_api = MagicMock()
        mock_sync_api.sync_playwright = mock_sync_playwright

        with patch.dict(sys.modules, {"playwright": MagicMock(), "playwright.sync_api": mock_sync_api}):
            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "inconclusive")


class TestScopeEnforcement(unittest.TestCase):
    """Verify that ScopeValidator correctly gates verifications."""

    def _load_validator(self):
        import importlib.util

        for mod_name in [
            "backend.app.scope.parser",
            "backend.app.scope.validator",
            "app.scope.parser",
            "pydantic",
        ]:
            sys.modules.pop(mod_name, None)

        # Stub pydantic so the parser can be loaded without the real package
        pydantic_stub = types.ModuleType("pydantic")

        class _BaseModel:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

        pydantic_stub.BaseModel = _BaseModel
        sys.modules["pydantic"] = pydantic_stub

        # Load parser first (validator imports it)
        spec = importlib.util.spec_from_file_location(
            "app.scope.parser",
            "backend/app/scope/parser.py",
        )
        parser_mod = importlib.util.module_from_spec(spec)
        sys.modules["app.scope.parser"] = parser_mod
        spec.loader.exec_module(parser_mod)

        spec2 = importlib.util.spec_from_file_location(
            "app.scope.validator",
            "backend/app/scope/validator.py",
        )
        validator_mod = importlib.util.module_from_spec(spec2)
        sys.modules["app.scope.validator"] = validator_mod
        spec2.loader.exec_module(validator_mod)
        return parser_mod, validator_mod

    def test_in_scope_host_passes(self) -> None:
        parser_mod, validator_mod = self._load_validator()
        rules = parser_mod.parse_scope_text("example.com")
        validator = validator_mod.ScopeValidator(rules)
        self.assertTrue(validator.is_in_scope("example.com"))

    def test_out_of_scope_host_blocked(self) -> None:
        parser_mod, validator_mod = self._load_validator()
        rules = parser_mod.parse_scope_text("example.com")
        validator = validator_mod.ScopeValidator(rules)
        self.assertFalse(validator.is_in_scope("evil.com"))

    def test_no_rules_blocks_all(self) -> None:
        """Default-deny: empty scope means nothing is in scope."""
        parser_mod, validator_mod = self._load_validator()
        rules = parser_mod.parse_scope_text("")
        validator = validator_mod.ScopeValidator(rules)
        self.assertFalse(validator.is_in_scope("example.com"))

    def test_check_or_raise_on_violation(self) -> None:
        parser_mod, validator_mod = self._load_validator()
        rules = parser_mod.parse_scope_text("example.com")
        validator = validator_mod.ScopeValidator(rules)
        with self.assertRaises(validator_mod.ScopeViolationError):
            validator.check_or_raise("evil.com")

    def test_wildcard_scope_covers_subdomain(self) -> None:
        parser_mod, validator_mod = self._load_validator()
        rules = parser_mod.parse_scope_text("*.example.com")
        validator = validator_mod.ScopeValidator(rules)
        self.assertTrue(validator.is_in_scope("sub.example.com"))
        self.assertFalse(validator.is_in_scope("other.com"))


if __name__ == "__main__":
    unittest.main()
