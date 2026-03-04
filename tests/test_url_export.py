"""Unit tests for backend.app.scans.url_normalizer and url_export.

These tests run without a live database or external services.
The normalizer is tested directly; url_export is tested by injecting
lightweight mock DB sessions.
"""

import json
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Stub out SQLAlchemy and backend internals so we can import the modules
# without a real DB driver installed.
# ---------------------------------------------------------------------------

def _build_mock(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


_MOCKED_MODULES = [
    "sqlalchemy",
    "sqlalchemy.orm",
    "backend",
    "backend.app",
    "backend.app.models",
    "backend.app.models.asset",
    "backend.app.models.endpoint",
]

_original_modules: dict = {}


def setUpModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        _original_modules[name] = sys.modules.get(name)
        sys.modules[name] = _build_mock(name)


def tearDownModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        original = _original_modules.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    # Remove cached imports so other test modules start clean
    for mod_name in list(sys.modules):
        if mod_name.startswith("backend.app.scans"):
            sys.modules.pop(mod_name, None)


def _load_normalizer():
    """Import url_normalizer after mocks are in place."""
    import importlib.util

    mod_name = "backend.app.scans.url_normalizer"
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(
        mod_name,
        "backend/app/scans/url_normalizer.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_url_export():
    """Import url_export after mocks and normalizer are in place."""
    import importlib.util

    # Ensure normalizer is loaded first
    norm = _load_normalizer()

    # Provide real asset / endpoint constants used by url_export
    asset_mock = sys.modules["backend.app.models.asset"]
    asset_mock.AssetType = type("AssetType", (), {"SUBDOMAIN": "subdomain", "IP": "ip", "CIDR": "cidr"})
    asset_mock.Asset = MagicMock()

    endpoint_mock = sys.modules["backend.app.models.endpoint"]
    endpoint_mock.Endpoint = MagicMock()

    scans_mock = _build_mock("backend.app.scans")
    scans_mock.url_normalizer = norm
    sys.modules["backend.app.scans"] = scans_mock
    sys.modules["backend.app.scans.url_normalizer"] = norm

    mod_name = "backend.app.scans.url_export"
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(
        mod_name,
        "backend/app/scans/url_export.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Tests for url_normalizer
# ---------------------------------------------------------------------------

class TestNormalizeUrl(unittest.TestCase):
    """Tests for normalize_url()."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.normalizer = _load_normalizer()
        cls._normalize_fn = staticmethod(cls.normalizer.normalize_url)

    def normalize(self, url: str):
        return self._normalize_fn(url)

    # --- basic canonicalisation ---

    def test_strips_whitespace(self) -> None:
        result = self.normalize("  http://example.com/  ")
        self.assertEqual(result, "http://example.com/")

    def test_lowercases_scheme(self) -> None:
        result = self.normalize("HTTP://Example.COM/path")
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("http://example.com/"))

    def test_lowercases_host(self) -> None:
        result = self.normalize("https://EXAMPLE.COM/")
        self.assertEqual(result, "https://example.com/")

    def test_removes_fragment(self) -> None:
        result = self.normalize("http://example.com/page#section")
        self.assertNotIn("#", result)

    def test_ensures_root_path(self) -> None:
        result = self.normalize("http://example.com")
        self.assertEqual(result, "http://example.com/")

    # --- default port removal ---

    def test_removes_default_port_80(self) -> None:
        result = self.normalize("http://example.com:80/")
        self.assertEqual(result, "http://example.com/")

    def test_removes_default_port_443(self) -> None:
        result = self.normalize("https://example.com:443/")
        self.assertEqual(result, "https://example.com/")

    def test_keeps_non_default_port(self) -> None:
        result = self.normalize("http://example.com:8080/")
        self.assertIn(":8080", result)

    def test_keeps_https_non_default_port(self) -> None:
        result = self.normalize("https://example.com:8443/api")
        self.assertIn(":8443", result)

    # --- query param sorting ---

    def test_sorts_query_params(self) -> None:
        a = self.normalize("http://example.com/search?z=1&a=2")
        b = self.normalize("http://example.com/search?a=2&z=1")
        self.assertEqual(a, b)

    def test_preserves_query_params(self) -> None:
        result = self.normalize("http://example.com/q?foo=bar")
        self.assertIn("foo=bar", result)

    # --- invalid inputs ---

    def test_returns_none_for_empty_string(self) -> None:
        self.assertIsNone(self.normalize(""))

    def test_returns_none_for_non_http_scheme(self) -> None:
        self.assertIsNone(self.normalize("ftp://example.com/"))

    def test_returns_none_for_no_host(self) -> None:
        self.assertIsNone(self.normalize("http:///path"))

    # --- dedup via normalization ---

    def test_dedup_http_80(self) -> None:
        a = self.normalize("http://example.com:80/path")
        b = self.normalize("http://example.com/path")
        self.assertEqual(a, b)

    def test_dedup_fragment_difference(self) -> None:
        a = self.normalize("http://example.com/#top")
        b = self.normalize("http://example.com/")
        self.assertEqual(a, b)


# ---------------------------------------------------------------------------
# Tests for url_export.export_scan_urls
# ---------------------------------------------------------------------------

class TestExportScanUrls(unittest.TestCase):
    """Tests for export_scan_urls() using mock DB objects."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_url_export()

    def _make_asset(self, value: str, asset_type: str = "subdomain", ports_json: str = "[]") -> MagicMock:
        asset = MagicMock()
        asset.asset_type = asset_type
        asset.value = value
        asset.ports_json = ports_json
        return asset

    def _make_endpoint(self, url: str) -> MagicMock:
        ep = MagicMock()
        ep.url = url
        return ep

    def _make_db(self, endpoints: list, assets: list) -> MagicMock:
        db = MagicMock()
        # url_export always queries Endpoint first, then Asset
        endpoint_query = MagicMock()
        endpoint_query.filter.return_value.all.return_value = endpoints

        asset_query = MagicMock()
        asset_query.filter.return_value.all.return_value = assets

        db.query.side_effect = [endpoint_query, asset_query]
        return db

    def test_writes_urls_txt(self) -> None:
        """export_scan_urls writes a urls.txt file."""
        db = self._make_db(
            endpoints=[self._make_endpoint("http://example.com/page")],
            assets=[self._make_asset("example.com")],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            self.assertTrue(result.exists())
            self.assertEqual(result.name, "urls.txt")

    def test_includes_endpoint_urls(self) -> None:
        """Endpoint URLs appear in the output."""
        db = self._make_db(
            endpoints=[self._make_endpoint("http://example.com/login")],
            assets=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            content = path.read_text()
            self.assertIn("http://example.com/login", content)

    def test_includes_fallback_root_urls(self) -> None:
        """http:// and https:// root URLs are generated for each asset."""
        db = self._make_db(
            endpoints=[],
            assets=[self._make_asset("sub.example.com")],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            content = path.read_text()
            self.assertIn("http://sub.example.com/", content)
            self.assertIn("https://sub.example.com/", content)

    def test_deduplicates_urls(self) -> None:
        """The same URL appearing multiple times is written only once."""
        db = self._make_db(
            endpoints=[
                self._make_endpoint("http://example.com/"),
                self._make_endpoint("http://example.com:80/"),
            ],
            assets=[self._make_asset("example.com")],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            lines = [line for line in path.read_text().splitlines() if line.strip()]
            http_roots = [line for line in lines if line == "http://example.com/"]
            self.assertEqual(len(http_roots), 1)

    def test_output_is_sorted(self) -> None:
        """URLs in urls.txt are in lexicographic order."""
        db = self._make_db(
            endpoints=[],
            assets=[
                self._make_asset("zebra.example.com"),
                self._make_asset("alpha.example.com"),
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            lines = [line for line in path.read_text().splitlines() if line.strip()]
            self.assertEqual(lines, sorted(lines))

    def test_skips_cidr_assets(self) -> None:
        """CIDR assets do not generate fallback URLs."""
        db = self._make_db(
            endpoints=[],
            assets=[self._make_asset("10.0.0.0/24", asset_type="cidr")],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            content = path.read_text().strip()
            self.assertEqual(content, "")

    def test_generates_port_based_urls(self) -> None:
        """Non-standard HTTP ports in ports_json produce extra URLs."""
        ports = json.dumps([{"port": 8080, "protocol": "tcp", "state": "open", "service": "http", "version": ""}])
        db = self._make_db(
            endpoints=[],
            assets=[self._make_asset("example.com", ports_json=ports)],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            content = path.read_text()
            self.assertIn("http://example.com:8080/", content)

    def test_generates_https_for_port_8443(self) -> None:
        """Port 8443 produces an https:// URL."""
        ports = json.dumps([{"port": 8443, "protocol": "tcp", "state": "open", "service": "https", "version": ""}])
        db = self._make_db(
            endpoints=[],
            assets=[self._make_asset("example.com", ports_json=ports)],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            content = path.read_text()
            self.assertIn("https://example.com:8443/", content)

    def test_skips_non_http_services(self) -> None:
        """Ports with non-HTTP services (e.g., ssh) are skipped."""
        ports = json.dumps([{"port": 8080, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""}])
        db = self._make_db(
            endpoints=[],
            assets=[self._make_asset("example.com", ports_json=ports)],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            content = path.read_text()
            self.assertNotIn(":8080", content)

    def test_creates_artifacts_dir(self) -> None:
        """The artifacts_dir is created if it does not exist."""
        db = self._make_db(endpoints=[], assets=[])
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "nested", "artifacts")
            self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=new_dir)
            self.assertTrue(os.path.isdir(new_dir))

    def test_empty_result_writes_empty_file(self) -> None:
        """When there are no URLs, urls.txt is written but empty."""
        db = self._make_db(endpoints=[], assets=[])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.mod.export_scan_urls(db, target_id=1, scan_id=1, artifacts_dir=tmpdir)
            self.assertEqual(path.read_text().strip(), "")


if __name__ == "__main__":
    unittest.main()
