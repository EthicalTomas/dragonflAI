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
        return scan

    def test_success_updates_status_to_failed_placeholder(self) -> None:
        """execute_scan sets status to failed (placeholder) and does not raise."""
        mod = _load_execute_scan()

        mock_scan = self._make_scan(1)
        mock_db = MagicMock()
        mock_db.get.return_value = mock_scan
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mod.ScanStatus = MagicMock()
        mod.ScanStatus.RUNNING = "running"
        mod.ScanStatus.FAILED = "failed"

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
        """execute_scan sets status to running before marking it failed."""
        mod = _load_execute_scan()

        status_sequence = []
        mock_scan = self._make_scan(1)

        def capture_commit():
            status_sequence.append(mock_scan.status)

        mock_db = MagicMock()
        mock_db.get.return_value = mock_scan
        mock_db.commit.side_effect = capture_commit
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mod.ScanStatus = MagicMock()
        mod.ScanStatus.RUNNING = "running"
        mod.ScanStatus.FAILED = "failed"

        mod.execute_scan(1)

        self.assertIn("running", status_sequence, "status was never set to running")


if __name__ == "__main__":
    unittest.main()
