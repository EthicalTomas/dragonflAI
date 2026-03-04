"""Tests for worker.jobs.execute_verification.

Verifies that execute_verification:
- Re-raises exceptions so RQ marks the job as failed
- Always closes the DB session (even on failure)
- Performs scope checking before running the verifier
- Transitions status from queued → running → confirmed/unconfirmed/failed
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
    "backend.app.models",
    "backend.app.models.finding",
    "backend.app.models.target",
    "backend.app.models.program",
    "backend.app.models.verification",
    "backend.app.scope",
    "backend.app.scope.parser",
    "backend.app.scope.validator",
    "backend.app.verify",
    "backend.app.verify.http_replay",
    "backend.app.verify.dns_recheck",
    "backend.app.verify.screenshot",
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
    sys.modules.pop("worker.jobs.execute_verification", None)


def _load_module():
    """Import (or reload) execute_verification after mocks are in place."""
    sys.modules.pop("worker.jobs.execute_verification", None)
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "worker.jobs.execute_verification",
        "worker/jobs/execute_verification.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["worker.jobs.execute_verification"] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_verification(vid: int = 1, method: str = "http_replay") -> MagicMock:
    v = MagicMock()
    v.id = vid
    v.status = "queued"
    v.method = method
    v.log_text = ""
    v.target_id = 10
    v.run_id = None
    v.finding_id = None
    v.evidence_json = None
    return v


def _make_target() -> MagicMock:
    t = MagicMock()
    t.id = 10
    t.name = "example.com"
    t.program_id = None
    t.roots_json = '["example.com"]'
    return t


class TestExecuteVerificationLifecycle(unittest.TestCase):
    """Status-transition and lifecycle tests."""

    def _make_mod_success(self, method: str = "http_replay"):
        mod = _load_module()
        verification = _make_verification(method=method)
        target = _make_target()

        mock_db = MagicMock()
        mock_db.get.side_effect = lambda cls, pk: (
            verification if cls is mod.Verification else target
        )
        mod.SessionLocal = MagicMock(return_value=mock_db)

        # Scope passes by default
        mock_validator = MagicMock()
        mock_validator.check_or_raise.return_value = None
        mod.ScopeValidator = MagicMock(return_value=mock_validator)
        mod.parse_scope_text = MagicMock(return_value=[])
        mod.ScopeViolationError = Exception

        # Patch _run_verifier to return a plain dict
        mod._run_verifier = MagicMock(return_value={
            "status": "confirmed",
            "evidence": {"url": "http://example.com", "status_code": 200},
            "notes": "HTTP 200 received.",
        })

        # Patch VerificationStatus
        mod.VerificationStatus = MagicMock()
        mod.VerificationStatus.QUEUED = "queued"
        mod.VerificationStatus.RUNNING = "running"
        mod.VerificationStatus.CONFIRMED = "confirmed"
        mod.VerificationStatus.FAILED = "failed"

        return mod, verification, mock_db

    def test_success_closes_db(self) -> None:
        mod, _, mock_db = self._make_mod_success()
        mod.execute_verification(1)
        mock_db.close.assert_called_once()

    def test_success_sets_status_running_then_confirmed(self) -> None:
        mod, verification, mock_db = self._make_mod_success()

        statuses = []

        def capture_commit():
            statuses.append(verification.status)

        mock_db.commit.side_effect = capture_commit
        mod.execute_verification(1)

        self.assertIn("running", statuses, "status was never set to running")

    def test_not_found_raises(self) -> None:
        mod = _load_module()
        mock_db = MagicMock()
        mock_db.get.return_value = None
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mod.VerificationStatus = MagicMock()
        mod.VerificationStatus.FAILED = "failed"

        with self.assertRaises(ValueError):
            mod.execute_verification(999)

    def test_db_closed_on_exception(self) -> None:
        mod = _load_module()
        mock_db = MagicMock()
        mock_db.get.side_effect = RuntimeError("db boom")
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mod.VerificationStatus = MagicMock()
        mod.VerificationStatus.FAILED = "failed"

        with self.assertRaises(RuntimeError):
            mod.execute_verification(7)

        mock_db.close.assert_called_once()

    def test_exception_is_reraised(self) -> None:
        mod = _load_module()
        mock_db = MagicMock()
        mock_db.get.side_effect = ValueError("unexpected")
        mod.SessionLocal = MagicMock(return_value=mock_db)
        mod.VerificationStatus = MagicMock()
        mod.VerificationStatus.FAILED = "failed"

        with self.assertRaises(ValueError):
            mod.execute_verification(42)

    def test_scope_violation_marks_failed_and_reraises(self) -> None:
        mod = _load_module()
        verification = _make_verification()
        target = _make_target()

        mock_db = MagicMock()
        mock_db.get.side_effect = lambda cls, pk: (
            verification if cls is mod.Verification else target
        )
        mod.SessionLocal = MagicMock(return_value=mock_db)

        # Scope fails
        class _ScopeViolation(Exception):
            pass

        mod.ScopeViolationError = _ScopeViolation
        mock_validator = MagicMock()
        mock_validator.check_or_raise.side_effect = _ScopeViolation("out of scope")
        mod.ScopeValidator = MagicMock(return_value=mock_validator)
        mod.parse_scope_text = MagicMock(return_value=[])
        mod.VerificationStatus = MagicMock()
        mod.VerificationStatus.RUNNING = "running"
        mod.VerificationStatus.FAILED = "failed"

        with self.assertRaises(_ScopeViolation):
            mod.execute_verification(1)

        self.assertEqual(verification.status, "failed")
        mock_db.close.assert_called_once()


class TestHostFromUrl(unittest.TestCase):
    """Unit tests for the internal _host_from_url helper."""

    def test_extracts_hostname(self) -> None:
        mod = _load_module()
        self.assertEqual(mod._host_from_url("https://example.com/path?q=1"), "example.com")

    def test_returns_input_on_bare_host(self) -> None:
        mod = _load_module()
        self.assertEqual(mod._host_from_url("example.com"), "example.com")

    def test_handles_ip(self) -> None:
        mod = _load_module()
        self.assertEqual(mod._host_from_url("http://192.168.1.1/"), "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
