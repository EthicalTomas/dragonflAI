"""Tests for worker.jobs.execute_run.

Verifies that execute_run re-raises exceptions so RQ marks jobs as failed.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch


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
    "backend.app.runs",
    "backend.app.runs.orchestrator",
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
    sys.modules.pop("worker.jobs.execute_run", None)


class TestExecuteRun(unittest.TestCase):
    """Tests for execute_run()."""

    def _load_execute_run(self):
        """Import (or reload) execute_run after mocks are in place."""
        sys.modules.pop("worker.jobs.execute_run", None)
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "worker.jobs.execute_run",
            "worker/jobs/execute_run.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["worker.jobs.execute_run"] = mod
        spec.loader.exec_module(mod)
        return mod

    def test_success_does_not_raise(self) -> None:
        """execute_run completes normally when orchestrator succeeds."""
        mod = self._load_execute_run()

        mock_db = MagicMock()
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mock_orchestrator = MagicMock()
        mock_orchestrator.execute.return_value = None
        mod.RunOrchestrator = MagicMock(return_value=mock_orchestrator)

        mod.execute_run(42)  # should not raise

        mod.RunOrchestrator.assert_called_once_with(42, mock_db)
        mock_orchestrator.execute.assert_called_once()
        mock_db.close.assert_called_once()

    def test_exception_is_reraised(self) -> None:
        """execute_run re-raises exceptions so RQ marks the job as failed."""
        mod = self._load_execute_run()

        mock_db = MagicMock()
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mock_orchestrator = MagicMock()
        mock_orchestrator.execute.side_effect = RuntimeError("orchestrator boom")
        mod.RunOrchestrator = MagicMock(return_value=mock_orchestrator)

        with self.assertRaises(RuntimeError):
            mod.execute_run(99)

    def test_db_closed_on_exception(self) -> None:
        """DB session is always closed, even when an exception is raised."""
        mod = self._load_execute_run()

        mock_db = MagicMock()
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mock_orchestrator = MagicMock()
        mock_orchestrator.execute.side_effect = ValueError("something went wrong")
        mod.RunOrchestrator = MagicMock(return_value=mock_orchestrator)

        with self.assertRaises(ValueError):
            mod.execute_run(7)

        mock_db.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
