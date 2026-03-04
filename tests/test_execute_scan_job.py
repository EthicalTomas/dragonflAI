"""Tests for worker.jobs.execute_scan.

Verifies that execute_scan re-raises exceptions so RQ marks jobs as failed,
and that status transitions are persisted correctly.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock


def _build_mock(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


_MOCKED_MODULES = [
    "backend",
    "backend.app",
    "backend.app.db",
    "backend.app.db.session",
    "backend.app.models",
    "backend.app.models.scan",
    "backend.app.scans",
    "backend.app.scans.nuclei_parser",
    "backend.app.scans.nuclei_runner",
    "backend.app.scans.url_export",
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
    sys.modules.pop("worker.jobs.execute_scan", None)


def _load_execute_scan():
    """Import (or reload) execute_scan after mocks are in place."""
    sys.modules.pop("worker.jobs.execute_scan", None)
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "worker.jobs.execute_scan",
        "worker/jobs/execute_scan.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["worker.jobs.execute_scan"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestExecuteScan(unittest.TestCase):
    """Tests for execute_scan()."""

    def _make_scan(self, scan_id: int = 1) -> MagicMock:
        scan = MagicMock()
        scan.id = scan_id
        scan.scanner = "nuclei"
        scan.status = "queued"
        scan.log_text = ""
        scan.target_id = 1
        scan.run_id = None
        return scan

    def _make_mod(self, scan_id: int = 1):
        """Load the module and wire up common mocks."""
        mod = _load_execute_scan()
        mock_scan = self._make_scan(scan_id)
        mock_db = MagicMock()
        mock_db.get.return_value = mock_scan
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mod.ScanStatus = MagicMock()
        mod.ScanStatus.RUNNING = "running"
        mod.ScanStatus.SUCCEEDED = "succeeded"
        mod.ScanStatus.FAILED = "failed"
        # preflight returns a plain dict so json.dumps works
        mod.preflight = MagicMock(return_value={
            "template_commit": "abc123",
            "templates_url": "https://github.com/projectdiscovery/nuclei-templates",
            "tags": "cve,misconfig,exposure,takeover",
            "etags": "dos,fuzz,intrusive,bruteforce",
            "flags": {"concurrency": 10, "rate_limit": 5, "timeout": 10, "retries": 1},
        })
        mod.run_nuclei = MagicMock(return_value="/tmp/nuclei.jsonl")
        mod.parse_nuclei_jsonl = MagicMock(return_value=3)
        mod.export_scan_urls = MagicMock()
        return mod, mock_scan, mock_db

    def test_success_updates_status_to_succeeded(self) -> None:
        """execute_scan sets status to succeeded on a successful run."""
        mod, mock_scan, mock_db = self._make_mod(1)

        mod.execute_scan(1)  # should not raise

        mock_db.commit.assert_called()
        mock_db.close.assert_called_once()

    def test_scan_not_found_raises(self) -> None:
        """execute_scan raises ValueError when scan does not exist."""
        mod = _load_execute_scan()

        mock_db = MagicMock()
        mock_db.get.return_value = None
        mod.SessionLocal = MagicMock(return_value=mock_db)

        with self.assertRaises(ValueError):
            mod.execute_scan(999)

    def test_exception_is_reraised(self) -> None:
        """execute_scan re-raises exceptions so RQ marks the job as failed."""
        mod = _load_execute_scan()

        mock_db = MagicMock()
        mock_db.get.side_effect = RuntimeError("db boom")
        mod.SessionLocal = MagicMock(return_value=mock_db)

        with self.assertRaises(RuntimeError):
            mod.execute_scan(42)

    def test_db_closed_on_exception(self) -> None:
        """DB session is always closed, even when an exception is raised."""
        mod = _load_execute_scan()

        mock_db = MagicMock()
        mock_db.get.side_effect = ValueError("something went wrong")
        mod.SessionLocal = MagicMock(return_value=mock_db)

        with self.assertRaises(ValueError):
            mod.execute_scan(7)

        mock_db.close.assert_called_once()

    def test_status_set_to_running_first(self) -> None:
        """execute_scan sets status to running before any other transitions."""
        mod, mock_scan, mock_db = self._make_mod(1)

        status_sequence = []

        def capture_commit():
            status_sequence.append(mock_scan.status)

        mock_db.commit.side_effect = capture_commit

        mod.execute_scan(1)

        self.assertIn("running", status_sequence, "status was never set to running")

    def test_preflight_failure_marks_scan_failed(self) -> None:
        """When preflight raises, execute_scan marks the scan FAILED and re-raises."""
        mod, mock_scan, mock_db = self._make_mod(1)
        mod.preflight = MagicMock(side_effect=RuntimeError("docker not found"))

        with self.assertRaises(RuntimeError):
            mod.execute_scan(1)

        self.assertEqual(mock_scan.status, "failed")
        mock_db.close.assert_called_once()

    def test_nuclei_failure_marks_scan_failed(self) -> None:
        """When run_nuclei raises, execute_scan marks the scan FAILED and re-raises."""
        mod, mock_scan, mock_db = self._make_mod(1)
        mod.run_nuclei = MagicMock(side_effect=RuntimeError("nuclei crashed"))

        with self.assertRaises(RuntimeError):
            mod.execute_scan(1)

        self.assertEqual(mock_scan.status, "failed")

    def test_config_json_stored(self) -> None:
        """execute_scan stores config_json with template_commit on the scan."""
        mod, mock_scan, mock_db = self._make_mod(1)

        mod.execute_scan(1)

        import json
        stored = json.loads(mock_scan.config_json)
        self.assertEqual(stored["template_commit"], "abc123")
        self.assertEqual(stored["scanner"], "nuclei")

    def test_parse_results_count_logged(self) -> None:
        """execute_scan records the finding count in the log."""
        mod, mock_scan, mock_db = self._make_mod(1)
        mod.parse_nuclei_jsonl = MagicMock(return_value=7)

        mod.execute_scan(1)

        self.assertIn("7", mock_scan.log_text)


if __name__ == "__main__":
    unittest.main()
