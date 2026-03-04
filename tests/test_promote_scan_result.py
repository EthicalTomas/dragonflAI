"""Tests for the scan-results promote endpoint.

Verifies that POST /scan-results/{id}/promote creates a Finding from a
ScanResult with appropriate defaults and that 404 is raised when the
ScanResult does not exist.
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
    "fastapi",
    "sqlalchemy",
    "sqlalchemy.orm",
    "backend",
    "backend.app",
    "backend.app.db",
    "backend.app.db.session",
    "backend.app.models",
    "backend.app.schemas",
    "backend.app.schemas.scan",
]

_original_modules: dict = {}


def setUpModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        _original_modules[name] = sys.modules.get(name)
        sys.modules[name] = _build_mock(name)

    router_mock = MagicMock()
    router_mock.post.return_value = lambda f: f
    router_mock.get.return_value = lambda f: f
    sys.modules["fastapi"].APIRouter.return_value = router_mock
    sys.modules["fastapi"].Depends.return_value = None
    sys.modules["fastapi"].HTTPException = Exception


def tearDownModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        original = _original_modules.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    sys.modules.pop("backend.app.api.routes.scan_results", None)


def _load_module():
    import importlib.util

    sys.modules.pop("backend.app.api.routes.scan_results", None)
    spec = importlib.util.spec_from_file_location(
        "backend.app.api.routes.scan_results",
        "backend/app/api/routes/scan_results.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["backend.app.api.routes.scan_results"] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_scan_result(
    result_id: int = 1,
    severity: str = "high",
    title: str = "SQL Injection found",
    tool: str = "nuclei",
    template_id: str | None = "sqli-basic",
    matched_url: str | None = "http://example.com/login",
    target_id: int = 5,
    scan_id: int = 10,
    run_id: int | None = None,
) -> MagicMock:
    sr = MagicMock()
    sr.id = result_id
    sr.scan_id = scan_id
    sr.target_id = target_id
    sr.run_id = run_id
    sr.tool = tool
    sr.severity = severity
    sr.template_id = template_id
    sr.title = title
    sr.matched_url = matched_url
    sr.tags_json = "[]"
    sr.evidence_json = "{}"
    sr.raw_json = "{}"
    return sr


class TestPromoteScanResult(unittest.TestCase):
    """Tests for the promote_scan_result endpoint."""

    def _make_db(self, scan_result: MagicMock | None) -> MagicMock:
        mock_db = MagicMock()
        mock_db.get.return_value = scan_result
        finding_mock = MagicMock()
        finding_mock.id = 99
        mock_db.refresh.side_effect = lambda obj: setattr(obj, "id", 99)
        return mock_db

    def test_promote_creates_finding(self) -> None:
        """promote_scan_result should add a Finding to the DB and return finding_id."""
        mod = _load_module()

        sr = _make_scan_result()
        mock_db = self._make_db(sr)
        mock_finding_class = MagicMock()
        created_finding = MagicMock()
        created_finding.id = 99
        mock_finding_class.return_value = created_finding
        mod.Finding = mock_finding_class

        result = mod.promote_scan_result(1, db=mock_db)

        mock_db.add.assert_called_once_with(created_finding)
        mock_db.commit.assert_called()
        self.assertEqual(result["scan_result_id"], 1)
        self.assertIn("finding_id", result)

    def test_promote_maps_severity_info_to_informational(self) -> None:
        """'info' severity from scanner should map to 'informational' Finding severity."""
        mod = _load_module()

        sr = _make_scan_result(severity="info")
        mock_db = self._make_db(sr)
        created_finding = MagicMock()
        created_finding.id = 42

        captured: dict = {}

        def capture(**kwargs):
            captured.update(kwargs)
            return created_finding

        mod.Finding = MagicMock(side_effect=lambda **kw: capture(**kw) or created_finding)
        mod.promote_scan_result(1, db=mock_db)

        self.assertEqual(captured.get("severity"), "informational")

    def test_promote_result_not_found_raises(self) -> None:
        """promote_scan_result raises HTTPException when ScanResult is missing."""
        mod = _load_module()

        mock_db = self._make_db(None)
        with self.assertRaises(Exception):
            mod.promote_scan_result(999, db=mock_db)

    def test_list_scan_results_filters(self) -> None:
        """list_scan_results applies target_id, scan_id, and severity filters."""
        mod = _load_module()

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.all.return_value = []

        mod.list_scan_results(scan_id=1, target_id=2, severity="high", db=mock_db)

        # filter should have been called (chained) for scan_id, target_id, severity
        self.assertGreaterEqual(mock_query.filter.call_count, 3)


if __name__ == "__main__":
    unittest.main()
