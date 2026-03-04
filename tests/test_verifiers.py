"""Unit tests for verification methods.

Tests cover:
- HttpReplayVerifier: success (confirmed/unconfirmed), network failure
- DnsRecheckVerifier: success, failure, expected IP matching
- ScreenshotVerifier: disabled by default, returns inconclusive
- Scope enforcement via ScopeValidator
- HttpReplayVerifier response body redaction and size limits
- VulnRouter per-vulnerability-type strategies
- Conservative verdict rules (weak signal → inconclusive)
- Evidence schema version and truncation metadata
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


# ---------------------------------------------------------------------------
# New tests: conservative verdicts, per-vuln routing, evidence schema
# ---------------------------------------------------------------------------


def _load_vuln_router():
    """Load VulnRouter from disk, injecting required dependencies."""
    import importlib.util

    for mod_name in [
        "backend.app.verify.base",
        "backend.app.verify.http_replay",
        "backend.app.verify.vuln_router",
    ]:
        sys.modules.pop(mod_name, None)

    for name, path in (
        ("backend.app.verify.base", "backend/app/verify/base.py"),
        ("backend.app.verify.http_replay", "backend/app/verify/http_replay.py"),
        ("backend.app.verify.vuln_router", "backend/app/verify/vuln_router.py"),
    ):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)

    return sys.modules["backend.app.verify.vuln_router"]


def _load_replay_mod():
    import importlib.util

    for mod_name in ["backend.app.verify.base", "backend.app.verify.http_replay"]:
        sys.modules.pop(mod_name, None)

    for name, path in (
        ("backend.app.verify.base", "backend/app/verify/base.py"),
        ("backend.app.verify.http_replay", "backend/app/verify/http_replay.py"),
    ):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)

    return sys.modules["backend.app.verify.http_replay"]


class TestHttpReplayConservativeVerdicts(unittest.TestCase):
    """Conservative verdict rules for HttpReplayVerifier."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.replay_mod = _load_replay_mod()
        self.HttpReplayVerifier = self.replay_mod.HttpReplayVerifier

    def _make_response(self, status_code: int, body: bytes = b"body") -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        resp.url = "http://example.com/"
        resp.content = body
        resp.headers = {}
        return resp

    def _call_verify(self, verifier, status_code: int, body: bytes = b"body") -> object:
        resp = self._make_response(status_code, body)
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.get.return_value = resp
            mock_cls.return_value = ctx
            return verifier.verify("http://example.com/")

    def test_no_markers_non5xx_is_inconclusive(self) -> None:
        """Without markers a 200 response must be inconclusive, not confirmed."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 200)
        self.assertEqual(result.status, "inconclusive")

    def test_no_markers_4xx_is_inconclusive(self) -> None:
        """Without markers a 4xx response must be inconclusive, not confirmed."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 404)
        self.assertEqual(result.status, "inconclusive")

    def test_no_markers_5xx_is_unconfirmed(self) -> None:
        """Without markers a 5xx response is unconfirmed (proof clearly fails)."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 500)
        self.assertEqual(result.status, "unconfirmed")

    def test_evidence_has_schema_version(self) -> None:
        """Evidence must include schema_version=1."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 200)
        self.assertEqual(result.evidence.get("schema_version"), 1)

    def test_evidence_has_method_field(self) -> None:
        """Evidence must include method='GET'."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 200)
        self.assertEqual(result.evidence.get("method"), "GET")

    def test_evidence_has_elapsed_s(self) -> None:
        """Evidence must include elapsed_s timing."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 200)
        self.assertIn("elapsed_s", result.evidence)
        self.assertIsInstance(result.evidence["elapsed_s"], float)

    def test_body_truncated_false_for_small_body(self) -> None:
        """body_truncated must be False for small responses."""
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 200, b"small")
        self.assertFalse(result.evidence.get("body_truncated"))

    def test_body_truncated_true_for_large_body(self) -> None:
        """body_truncated must be True when response exceeds _MAX_BODY_BYTES."""
        max_bytes = self.replay_mod._MAX_BODY_BYTES
        verifier = self.HttpReplayVerifier()
        result = self._call_verify(verifier, 200, b"X" * (max_bytes + 1))
        self.assertTrue(result.evidence.get("body_truncated"))

    def test_x_amz_security_token_redacted(self) -> None:
        """x-amz-security-token must be redacted from evidence."""
        verifier = self.HttpReplayVerifier()
        resp = self._make_response(200, b"body")
        resp.headers = {"x-amz-security-token": "AQoXnyc...", "content-type": "text/html"}
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.get.return_value = resp
            mock_cls.return_value = ctx
            result = verifier.verify("http://example.com/")

        resp_hdrs = result.evidence.get("response_headers", {})
        self.assertEqual(resp_hdrs.get("x-amz-security-token"), "[REDACTED]")
        self.assertNotIn("AQoXnyc", str(resp_hdrs))

    def test_proxy_authorization_redacted(self) -> None:
        """proxy-authorization must be redacted."""
        verifier = self.HttpReplayVerifier()
        resp = self._make_response(200, b"body")
        resp.headers = {"proxy-authorization": "Basic abc123"}
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.get.return_value = resp
            mock_cls.return_value = ctx
            result = verifier.verify("http://example.com/")

        self.assertEqual(result.evidence["response_headers"].get("proxy-authorization"), "[REDACTED]")

    def test_transport_error_evidence_has_schema_version(self) -> None:
        """Transport error evidence must still include schema_version."""
        import httpx as _httpx

        verifier = self.HttpReplayVerifier()
        with patch("httpx.Client") as mock_cls:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.get.side_effect = _httpx.ConnectError("refused")
            mock_cls.return_value = ctx
            result = verifier.verify("http://example.com/")

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.evidence.get("schema_version"), 1)


class TestVulnRouterClassification(unittest.TestCase):
    """Tests for the _classify() routing function."""

    def setUp(self) -> None:
        self.router_mod = _load_vuln_router()

    def test_open_redirect_by_vuln_type(self) -> None:
        self.assertEqual(self.router_mod._classify("Open Redirect", None, None), "open_redirect")

    def test_open_redirect_by_tag(self) -> None:
        self.assertEqual(self.router_mod._classify(None, None, ["open-redirect"]), "open_redirect")

    def test_open_redirect_by_title(self) -> None:
        self.assertEqual(self.router_mod._classify(None, "Open Redirect in login", None), "open_redirect")

    def test_xss_by_vuln_type(self) -> None:
        self.assertEqual(self.router_mod._classify("XSS", None, None), "reflected_xss")

    def test_xss_by_cross_site_scripting(self) -> None:
        self.assertEqual(self.router_mod._classify("Cross-Site Scripting", None, None), "reflected_xss")

    def test_xss_by_tag(self) -> None:
        self.assertEqual(self.router_mod._classify(None, None, ["xss"]), "reflected_xss")

    def test_takeover_by_vuln_type(self) -> None:
        self.assertEqual(self.router_mod._classify("Subdomain Takeover", None, None), "takeover")

    def test_takeover_by_tag(self) -> None:
        self.assertEqual(self.router_mod._classify(None, None, ["subdomain-takeover"]), "takeover")

    def test_sensitive_file_by_vuln_type(self) -> None:
        self.assertEqual(self.router_mod._classify("Sensitive File Exposure", None, None), "sensitive_file")

    def test_sensitive_file_by_title(self) -> None:
        self.assertEqual(self.router_mod._classify(None, "Exposed Admin Panel", None), "sensitive_file")

    def test_generic_fallback(self) -> None:
        self.assertEqual(self.router_mod._classify("SQL Injection", None, None), "generic")

    def test_vuln_type_priority_over_tags(self) -> None:
        """vulnerability_type classification takes priority over tags."""
        result = self.router_mod._classify("XSS", "Redirect page", ["open-redirect"])
        self.assertEqual(result, "reflected_xss")


class TestVulnRouterOpenRedirect(unittest.TestCase):
    """VulnRouter open-redirect strategy."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.router_mod = _load_vuln_router()

    def _make_redirect_resp(self, location: str) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 302
        resp.content = b""
        resp.url = "http://example.com/"
        resp.headers = {"location": location}
        return resp

    def test_confirmed_when_canary_in_location(self) -> None:
        """Open redirect confirmed when Location header contains the canary domain."""
        canary = self.router_mod._REDIRECT_CANARY
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_redirect_resp(f"https://{canary}/"), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/login", vulnerability_type="Open Redirect")

        self.assertEqual(result.status, "confirmed")
        self.assertIn(canary, result.evidence.get("location_header", ""))

    def test_inconclusive_when_no_canary_redirect(self) -> None:
        """Open redirect inconclusive when no param triggers a canary redirect."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_redirect_resp("http://example.com/home"), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/login", vulnerability_type="Open Redirect")

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("params_tried", result.evidence)

    def test_inconclusive_on_transport_error(self) -> None:
        """Open redirect inconclusive when all probes fail."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return None, 0.1, "connection refused"

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=[]):
                result = router.route("http://example.com/login", vulnerability_type="Open Redirect")

        self.assertEqual(result.status, "inconclusive")


class TestVulnRouterReflectedXss(unittest.TestCase):
    """VulnRouter reflected-XSS strategy."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.router_mod = _load_vuln_router()

    def _make_resp(self, body: bytes, status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.url = "http://example.com/"
        resp.headers = {}
        return resp

    def test_confirmed_when_marker_reflected(self) -> None:
        """XSS confirmed when marker appears in response body."""
        marker = self.router_mod._XSS_MARKER
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(f"<html>search: {marker}</html>".encode()), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/search", vulnerability_type="XSS")

        self.assertEqual(result.status, "confirmed")
        self.assertTrue(result.evidence.get("marker_reflected"))

    def test_unconfirmed_when_marker_not_reflected(self) -> None:
        """XSS unconfirmed when marker not in response body."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(b"<html>hello world</html>"), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/search", vulnerability_type="XSS")

        self.assertEqual(result.status, "unconfirmed")
        self.assertFalse(result.evidence.get("marker_reflected"))

    def test_inconclusive_on_transport_error(self) -> None:
        """XSS inconclusive on transport error."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return None, 0.1, "timeout"

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=[]):
                result = router.route("http://example.com/search", vulnerability_type="XSS")

        self.assertEqual(result.status, "inconclusive")


class TestVulnRouterSensitiveFile(unittest.TestCase):
    """VulnRouter exposed admin/sensitive-file strategy."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.router_mod = _load_vuln_router()

    def _make_resp(self, body: bytes, status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.url = "http://example.com/admin"
        resp.headers = {}
        return resp

    def test_confirmed_with_admin_title_in_body(self) -> None:
        """Sensitive file confirmed when admin panel title marker found."""
        router = self.router_mod.VulnRouter()
        body = b"<html><head><title>Admin Dashboard</title></head></html>"

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(body), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/admin", vulnerability_type="Exposed Admin Panel")

        self.assertEqual(result.status, "confirmed")
        self.assertIn("matched_pattern", result.evidence)

    def test_inconclusive_on_200_without_marker(self) -> None:
        """Sensitive file inconclusive on bare 200 with no admin marker."""
        router = self.router_mod.VulnRouter()
        body = b"<html><body>Welcome to our site</body></html>"

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(body), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/admin", vulnerability_type="Sensitive Exposure")

        self.assertEqual(result.status, "inconclusive")

    def test_unconfirmed_on_404(self) -> None:
        """Sensitive file unconfirmed on 404."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(b"Not Found", 404), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/admin", vulnerability_type="Exposed Admin Panel")

        self.assertEqual(result.status, "unconfirmed")

    def test_inconclusive_on_401(self) -> None:
        """Sensitive file inconclusive on 401 auth wall."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(b"Unauthorized", 401), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/admin", vulnerability_type="Sensitive Exposure")

        self.assertEqual(result.status, "inconclusive")


class TestVulnRouterTakeover(unittest.TestCase):
    """VulnRouter subdomain-takeover strategy."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.router_mod = _load_vuln_router()

    def _make_resp(self, body: bytes, status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.url = "http://sub.example.com/"
        resp.headers = {}
        return resp

    def test_confirmed_on_known_provider_fingerprint(self) -> None:
        """Takeover confirmed when a known provider fingerprint is found."""
        router = self.router_mod.VulnRouter()
        body = b"There isn't a GitHub Pages site here"

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(body), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["185.199.108.153"]):
                result = router.route("http://sub.example.com/", vulnerability_type="Subdomain Takeover")

        self.assertEqual(result.status, "confirmed")
        self.assertEqual(result.evidence.get("matched_provider"), "GitHub Pages")

    def test_inconclusive_on_nxdomain(self) -> None:
        """Takeover inconclusive when host does not resolve (NXDOMAIN)."""
        router = self.router_mod.VulnRouter()

        with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=[]):
            result = router.route("http://sub.example.com/", vulnerability_type="Subdomain Takeover")

        self.assertEqual(result.status, "inconclusive")
        self.assertTrue(result.evidence.get("dns_nxdomain"))

    def test_inconclusive_when_no_fingerprint_matches(self) -> None:
        """Takeover inconclusive when DNS resolves but no fingerprint matched."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(b"<html>Some normal page</html>"), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
            result = router.route("http://sub.example.com/", vulnerability_type="Subdomain Takeover")

        self.assertEqual(result.status, "inconclusive")
        self.assertNotIn("matched_provider", result.evidence)


class TestVulnRouterGeneric(unittest.TestCase):
    """VulnRouter generic fallback strategy."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.router_mod = _load_vuln_router()

    def _make_resp(self, body: bytes = b"page content", status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.url = "http://example.com/"
        resp.headers = {}
        return resp

    def test_generic_always_inconclusive_on_200(self) -> None:
        """Generic strategy must return inconclusive even on a 200 response."""
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                result = router.route("http://example.com/", vulnerability_type="SQL Injection")

        self.assertEqual(result.status, "inconclusive")

    def test_generic_evidence_has_schema_version(self) -> None:
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=[]):
                result = router.route("http://example.com/", vulnerability_type="SSRF")

        self.assertEqual(result.evidence.get("schema_version"), 1)


class TestVulnRouterEvidenceSchema(unittest.TestCase):
    """Evidence schema version and truncation metadata consistency."""

    def setUp(self) -> None:
        if not _HTTPX_AVAILABLE:
            self.skipTest("httpx not available")
        self.router_mod = _load_vuln_router()

    def _make_resp(self, body: bytes = b"hello", status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.content = body
        resp.url = "http://example.com/"
        resp.headers = {"content-type": "text/html"}
        return resp

    def _run_route(self, vulnerability_type: str) -> object:
        router = self.router_mod.VulnRouter()

        def fake_get(_self, url, *, follow_redirects=False, extra_params=None):
            return self._make_resp(), 0.1, None

        with patch.object(self.router_mod.VulnRouter, "_get", fake_get):
            with patch.object(self.router_mod.VulnRouter, "_resolve_ips", return_value=["1.2.3.4"]):
                return router.route("http://example.com/", vulnerability_type=vulnerability_type)

    def test_xss_evidence_has_schema_version(self) -> None:
        result = self._run_route("XSS")
        self.assertEqual(result.evidence.get("schema_version"), 1)

    def test_sensitive_file_evidence_has_schema_version(self) -> None:
        result = self._run_route("Sensitive Exposure")
        self.assertEqual(result.evidence.get("schema_version"), 1)

    def test_takeover_evidence_has_schema_version(self) -> None:
        result = self._run_route("Subdomain Takeover")
        self.assertEqual(result.evidence.get("schema_version"), 1)

    def test_sensitive_file_body_truncated_present(self) -> None:
        """body_truncated field must be present in sensitive-file evidence."""
        result = self._run_route("Sensitive Exposure")
        self.assertIn("body_truncated", result.evidence)
