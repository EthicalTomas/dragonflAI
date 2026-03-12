"""Regression tests for auto-verify severity threshold logic.

Verifies that:
- ``_get_auto_verify_severities`` returns the correct set for each
  ``AUTO_VERIFY_MIN_SEVERITY`` value.
- ``_queue_auto_verifications`` only enqueues results whose severity is at or
  above the configured threshold.
- An invalid ``AUTO_VERIFY_MIN_SEVERITY`` falls back to ``"high"``.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Minimal stubs for heavy dependencies that pipeline.py imports at module load
# ---------------------------------------------------------------------------

def _create_mock_module(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


_MOCKED_MODULES = [
    "redis",
    "rq",
    "rq.job",
    "sqlalchemy",
    "sqlalchemy.orm",
    "backend",
    "backend.app",
    "backend.app.core",
    "backend.app.core.config",
    "backend.app.db",
    "backend.app.db.session",
    "backend.app.detection",
    "backend.app.detection.orchestrator",
    "backend.app.models",
    "backend.app.models.run",
    "backend.app.parsers",
    "backend.app.parsers.burp_parser",
    "backend.app.parsers.httpx_parser",
    "backend.app.parsers.nmap_parser",
    "backend.app.parsers.subfinder_parser",
    "backend.app.parsers.zap_parser",
    "backend.app.scope",
    "backend.app.scope.validator",
    "backend.app.services",
    "backend.app.services.asset_service",
    "backend.app.services.endpoint_service",
    "backend.app.services.runs_service",
    "backend.app.runs",
    "backend.app.runs.preflight",
    "backend.app.tools",
    "backend.app.tools.dnsx",
    "backend.app.tools.httpx_probe",
    "backend.app.tools.nmap",
    "backend.app.tools.subfinder",
]

_original_modules: dict = {}


def setUpModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        _original_modules[name] = sys.modules.get(name)
        sys.modules[name] = _create_mock_module(name)


def tearDownModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        original = _original_modules.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    sys.modules.pop("backend.app.runs.pipeline", None)


def _load_pipeline():
    """Import (or reload) pipeline after stubs are installed."""
    import importlib

    sys.modules.pop("backend.app.runs.pipeline", None)
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "backend.app.runs.pipeline",
        "backend/app/runs/pipeline.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["backend.app.runs.pipeline"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestGetAutoVerifySeverities(unittest.TestCase):
    """Unit tests for the _get_auto_verify_severities helper."""

    def _call(self, min_severity: str, pipeline_mod):
        """Patch settings.auto_verify_min_severity and call the helper."""
        pipeline_mod.settings.auto_verify_min_severity = min_severity
        return pipeline_mod._get_auto_verify_severities()

    def test_high_default_includes_high_and_critical(self) -> None:
        """When min severity is 'high', only high and critical are returned."""
        pipeline = _load_pipeline()
        result = self._call("high", pipeline)
        self.assertEqual(result, frozenset({"high", "critical"}))

    def test_medium_includes_medium_high_critical(self) -> None:
        """When min severity is 'medium', medium/high/critical are returned."""
        pipeline = _load_pipeline()
        result = self._call("medium", pipeline)
        self.assertEqual(result, frozenset({"medium", "high", "critical"}))

    def test_critical_includes_only_critical(self) -> None:
        """When min severity is 'critical', only critical is returned."""
        pipeline = _load_pipeline()
        result = self._call("critical", pipeline)
        self.assertEqual(result, frozenset({"critical"}))

    def test_low_includes_low_and_above(self) -> None:
        """When min severity is 'low', low/medium/high/critical are returned."""
        pipeline = _load_pipeline()
        result = self._call("low", pipeline)
        self.assertEqual(result, frozenset({"low", "medium", "high", "critical"}))

    def test_info_includes_all_severities(self) -> None:
        """When min severity is 'info', all severity levels are returned."""
        pipeline = _load_pipeline()
        result = self._call("info", pipeline)
        self.assertEqual(result, frozenset({"info", "low", "medium", "high", "critical"}))

    def test_invalid_severity_falls_back_to_high(self) -> None:
        """An unrecognised severity value falls back to 'high'."""
        pipeline = _load_pipeline()
        with self.assertLogs("backend.app.runs.pipeline", level="WARNING"):
            result = self._call("bogus", pipeline)
        self.assertEqual(result, frozenset({"high", "critical"}))

    def test_case_insensitive(self) -> None:
        """The comparison is case-insensitive (e.g. 'HIGH' == 'high')."""
        pipeline = _load_pipeline()
        result = self._call("HIGH", pipeline)
        self.assertEqual(result, frozenset({"high", "critical"}))


class TestQueueAutoVerificationsSeverityFilter(unittest.TestCase):
    """Ensure _queue_auto_verifications only enqueues results that meet the threshold."""

    def _make_result(self, severity: str, result_id: int = 1) -> MagicMock:
        r = MagicMock()
        r.id = result_id
        r.severity = severity
        return r

    def _run(self, min_severity: str, db_results: list) -> int:
        """Run _queue_auto_verifications with a mocked DB and return enqueue call count."""
        pipeline = _load_pipeline()
        pipeline.settings.auto_verify_min_severity = min_severity
        pipeline.settings.redis_url = "redis://localhost:6379/0"
        pipeline.settings.job_timeout_seconds = 3600

        mock_db = MagicMock()

        # Build a chain: db.query().filter().all() returns db_results
        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_filter.all.return_value = db_results
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query

        mock_queue = MagicMock()

        # Stub the deferred imports inside _queue_auto_verifications
        mock_scan_result = MagicMock()
        mock_verification = MagicMock()
        mock_verification_status = MagicMock()
        mock_verification_status.QUEUED = "queued"
        mock_redis = MagicMock()
        mock_queue_cls = MagicMock(return_value=mock_queue)
        mock_retry = MagicMock()

        with (
            patch.dict(
                sys.modules,
                {
                    "backend.app.models.scan": MagicMock(ScanResult=mock_scan_result),
                    "backend.app.models.verification": MagicMock(
                        Verification=mock_verification,
                        VerificationStatus=mock_verification_status,
                    ),
                    "redis": MagicMock(Redis=mock_redis),
                    "rq": MagicMock(Queue=mock_queue_cls),
                    "rq.job": MagicMock(Retry=mock_retry),
                },
            ),
        ):
            pipeline._queue_auto_verifications(
                db=mock_db,
                scan_id=1,
                target_id=10,
                run_id=None,
            )

        return mock_queue.enqueue.call_count

    def test_high_min_severity_enqueues_high_and_critical_results(self) -> None:
        """With AUTO_VERIFY_MIN_SEVERITY=high, only high/critical rows are enqueued."""
        results = [
            self._make_result("high", 1),
            self._make_result("critical", 2),
        ]
        count = self._run("high", results)
        self.assertEqual(count, 2)

    def test_medium_min_severity_enqueues_three_results(self) -> None:
        """With AUTO_VERIFY_MIN_SEVERITY=medium, medium/high/critical are enqueued."""
        results = [
            self._make_result("medium", 1),
            self._make_result("high", 2),
            self._make_result("critical", 3),
        ]
        count = self._run("medium", results)
        self.assertEqual(count, 3)

    def test_no_matching_results_enqueues_nothing(self) -> None:
        """When no results meet the threshold, nothing is enqueued."""
        count = self._run("high", [])
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
