"""Tests for backend.app.scans.nuclei_parser.

Runs without a live database by using a mock SQLAlchemy session.
"""

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock


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
    "backend.app.models.scan",
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
    sys.modules.pop("backend.app.scans.nuclei_parser", None)


def _load_parser():
    """Load nuclei_parser after mocks are in place."""
    mod_name = "backend.app.scans.nuclei_parser"
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(
        mod_name,
        "backend/app/scans/nuclei_parser.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_entry(**overrides) -> dict:
    """Return a minimal nuclei JSONL entry dict."""
    base = {
        "template-id": "cve-2021-44228",
        "info": {
            "name": "Log4Shell RCE",
            "severity": "critical",
            "tags": ["cve", "rce"],
        },
        "matched-at": "http://example.com/path",
        "host": "example.com",
        "type": "http",
    }
    base.update(overrides)
    return base


class TestParseNucleiJsonl(unittest.TestCase):
    """Tests for parse_nuclei_jsonl()."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_parser()
        # Replace ScanResult with a simple data class so we can inspect args
        cls.captured: list = []

        class FakeScanResult:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)
                cls.captured.append(self)

        cls.mod.ScanResult = FakeScanResult

    def setUp(self) -> None:
        type(self).captured.clear()

    def _make_db(self) -> MagicMock:
        db = MagicMock()
        return db

    def _write_jsonl(self, entries: list, tmpdir: str) -> Path:
        path = Path(tmpdir) / "nuclei.jsonl"
        lines = [json.dumps(e) for e in entries]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_returns_zero_for_missing_file(self) -> None:
        mod = self.mod
        db = self._make_db()
        count = mod.parse_nuclei_jsonl(db, "/nonexistent/nuclei.jsonl", scan_id=1, target_id=1)
        self.assertEqual(count, 0)
        db.commit.assert_not_called()

    def test_parses_single_entry(self) -> None:
        mod = self.mod
        db = self._make_db()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([_make_entry()], tmpdir)
            count = mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=2)

        self.assertEqual(count, 1)
        db.add.assert_called_once()
        db.commit.assert_called_once()

    def test_maps_fields_correctly(self) -> None:
        mod = self.mod
        db = self._make_db()
        entry = _make_entry(request="GET / HTTP/1.1", response="HTTP/1.1 200 OK")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=5, target_id=3, run_id=7)

        result = self.captured[-1]
        self.assertEqual(result.scan_id, 5)
        self.assertEqual(result.target_id, 3)
        self.assertEqual(result.run_id, 7)
        self.assertEqual(result.tool, "nuclei")
        self.assertEqual(result.template_id, "cve-2021-44228")
        self.assertEqual(result.title, "Log4Shell RCE")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.matched_url, "http://example.com/path")

    def test_tags_stored_as_json_list(self) -> None:
        mod = self.mod
        db = self._make_db()
        entry = _make_entry()
        entry["info"]["tags"] = ["cve", "rce", "log4j"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        tags = json.loads(result.tags_json)
        self.assertIn("cve", tags)
        self.assertIn("rce", tags)

    def test_tags_as_comma_string_split(self) -> None:
        mod = self.mod
        db = self._make_db()
        entry = _make_entry()
        entry["info"]["tags"] = "cve,rce,log4j"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        tags = json.loads(result.tags_json)
        self.assertIn("cve", tags)

    def test_evidence_json_captures_request_response(self) -> None:
        mod = self.mod
        db = self._make_db()
        entry = _make_entry(request="GET / HTTP/1.1\r\n", response="HTTP/1.1 200 OK\r\n")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        evidence = json.loads(result.evidence_json)
        self.assertIn("request", evidence)
        self.assertIn("response", evidence)

    def test_raw_json_stores_original_line(self) -> None:
        mod = self.mod
        db = self._make_db()
        entry = _make_entry()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        stored = json.loads(result.raw_json)
        self.assertEqual(stored["template-id"], "cve-2021-44228")

    def test_skips_blank_lines(self) -> None:
        mod = self.mod
        db = self._make_db()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nuclei.jsonl"
            path.write_text(
                "\n" + json.dumps(_make_entry()) + "\n\n" + json.dumps(_make_entry()) + "\n",
                encoding="utf-8",
            )
            count = mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        self.assertEqual(count, 2)

    def test_skips_invalid_json_lines(self) -> None:
        mod = self.mod
        db = self._make_db()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nuclei.jsonl"
            path.write_text(
                "not-json\n" + json.dumps(_make_entry()) + "\n",
                encoding="utf-8",
            )
            count = mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        self.assertEqual(count, 1)

    def test_multiple_entries_all_added(self) -> None:
        mod = self.mod
        db = self._make_db()
        entries = [_make_entry(), _make_entry(), _make_entry()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl(entries, tmpdir)
            count = mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        self.assertEqual(count, 3)
        self.assertEqual(db.add.call_count, 3)

    def test_no_commit_when_no_results(self) -> None:
        mod = self.mod
        db = self._make_db()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nuclei.jsonl"
            path.write_text("", encoding="utf-8")
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        db.commit.assert_not_called()

    def test_fallback_title_uses_template_id(self) -> None:
        """When info.name is absent, template-id is used as title."""
        mod = self.mod
        db = self._make_db()
        entry = _make_entry()
        del entry["info"]["name"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        self.assertEqual(result.title, "cve-2021-44228")

    def test_severity_defaults_to_informational(self) -> None:
        """Missing severity defaults to 'informational'."""
        mod = self.mod
        db = self._make_db()
        entry = _make_entry()
        del entry["info"]["severity"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        self.assertEqual(result.severity, "informational")

    def test_matched_url_falls_back_to_host(self) -> None:
        """When matched-at is absent, host is used as matched_url."""
        mod = self.mod
        db = self._make_db()
        entry = _make_entry()
        del entry["matched-at"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_jsonl([entry], tmpdir)
            mod.parse_nuclei_jsonl(db, path, scan_id=1, target_id=1)

        result = self.captured[-1]
        self.assertEqual(result.matched_url, "example.com")


if __name__ == "__main__":
    unittest.main()
