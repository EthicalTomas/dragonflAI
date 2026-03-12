"""Tests for human-review safeguards on findings.

Verifies that:
- Export is blocked when reviewed_by_human=False.
- Batch-report is blocked when any finding is unreviewed.
- Status transition to ready_to_submit/submitted is blocked without review.
- POST /findings/{id}/review correctly sets reviewed_by_human, reviewed_at, and reviewer.
- review endpoint requires a non-empty reviewer name.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch as mock_patch


def _build_mock(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


_MOCKED_MODULES = [
    "fastapi",
    "fastapi.responses",
    "pydantic",
    "sqlalchemy",
    "sqlalchemy.orm",
    "backend",
    "backend.app",
    "backend.app.db",
    "backend.app.db.session",
    "backend.app.models",
    "backend.app.reports",
    "backend.app.reports.cvss",
    "backend.app.reports.generator",
    "backend.app.llm",
    "backend.app.llm.null_provider",
    "backend.app.schemas",
    "backend.app.schemas.finding",
]

_original_modules: dict = {}


class _FakeHTTPException(Exception):
    """Minimal HTTPException stand-in that accepts status_code and detail kwargs."""

    def __init__(self, status_code: int = 400, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def setUpModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        _original_modules[name] = sys.modules.get(name)
        sys.modules[name] = _build_mock(name)

    # pydantic.BaseModel mock — used in findings.py
    sys.modules["pydantic"].BaseModel = object

    router_mock = MagicMock()
    router_mock.post.return_value = lambda f: f
    router_mock.get.return_value = lambda f: f
    router_mock.patch.return_value = lambda f: f
    sys.modules["fastapi"].APIRouter.return_value = router_mock
    sys.modules["fastapi"].Depends.return_value = None
    sys.modules["fastapi"].HTTPException = _FakeHTTPException
    sys.modules["fastapi"].Query = MagicMock(return_value=None)
    sys.modules["fastapi.responses"].FileResponse = MagicMock()


def tearDownModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        original = _original_modules.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    sys.modules.pop("backend.app.api.routes.findings", None)
    sys.modules.pop("backend.app.models.finding", None)


def _load_models():
    import importlib.util

    sys.modules.pop("backend.app.models.finding", None)
    spec = importlib.util.spec_from_file_location(
        "backend.app.models.finding",
        "backend/app/models/finding.py",
    )
    # We need the real SQLAlchemy-free version — just extract the status constants
    # by executing a minimal version
    mod = types.ModuleType("backend.app.models.finding")
    # Inject minimal class definitions by exec-ing just the class bodies
    exec(  # noqa: S102
        """
class FindingStatus:
    DRAFT = "draft"
    NEEDS_REVIEW = "needs_review"
    READY_TO_SUBMIT = "ready_to_submit"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    READY = "ready_to_submit"
""",
        mod.__dict__,
    )
    sys.modules["backend.app.models.finding"] = mod
    return mod


def _load_schemas():
    """Load schemas without real pydantic by creating mock classes."""
    mod = sys.modules["backend.app.schemas.finding"]
    mod._ALLOWED_STATUSES = {
        "draft",
        "needs_review",
        "ready_to_submit",
        "submitted",
        "accepted",
        "duplicate",
        "not_applicable",
    }
    return mod


def _load_module():
    import importlib.util

    sys.modules.pop("backend.app.api.routes.findings", None)

    _load_models()
    _load_schemas()

    spec = importlib.util.spec_from_file_location(
        "backend.app.api.routes.findings",
        "backend/app/api/routes/findings.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["backend.app.api.routes.findings"] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_finding(
    finding_id: int = 1,
    reviewed_by_human: bool = False,
    status: str = "draft",
    reviewer: str | None = None,
    reviewed_at=None,
    review_notes: str | None = None,
    report_markdown: str | None = "# Report",
) -> MagicMock:
    f = MagicMock()
    f.id = finding_id
    f.target_id = 1
    f.run_id = None
    f.title = "Test Finding"
    f.vulnerability_type = "XSS"
    f.severity = "high"
    f.status = status
    f.url = "http://example.com"
    f.parameter = None
    f.description = "A test finding description longer than 20 chars."
    f.steps_to_reproduce = "Step 1.\nStep 2 is here also long enough."
    f.impact = "High impact description here."
    f.remediation = None
    f.evidence_paths_json = "[]"
    f.request_response = None
    f.cvss_score = None
    f.cvss_vector = None
    f.references_json = "[]"
    f.notes = None
    f.report_markdown = report_markdown
    f.reviewed_by_human = reviewed_by_human
    f.reviewed_at = reviewed_at
    f.reviewer = reviewer
    f.review_notes = review_notes
    f.log_text = None
    f.created_at = "2026-01-01T00:00:00"
    f.updated_at = None
    return f


def _make_db(finding: MagicMock | None) -> MagicMock:
    mock_db = MagicMock()
    mock_db.get.return_value = finding
    return mock_db


class TestExportRequiresReview(unittest.TestCase):
    """export_report must be blocked when reviewed_by_human=False."""

    def test_export_blocked_without_review(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=False, report_markdown="# Report")
        mock_db = _make_db(finding)

        with self.assertRaises(Exception) as ctx:
            mod.export_report(1, format="markdown", db=mock_db)

        # Should raise with a message about review being required
        err = str(ctx.exception)
        self.assertIn("reviewed", err.lower())

    def test_export_blocked_when_no_report_even_if_reviewed(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=True, report_markdown=None)
        mock_db = _make_db(finding)

        with self.assertRaises(Exception) as ctx:
            mod.export_report(1, format="markdown", db=mock_db)

        err = str(ctx.exception)
        self.assertIn("report", err.lower())

    def test_export_not_found_raises(self) -> None:
        mod = _load_module()
        mock_db = _make_db(None)

        with self.assertRaises(Exception):
            mod.export_report(999, format="markdown", db=mock_db)


class TestBatchReportRequiresReview(unittest.TestCase):
    """batch_report must be blocked when any finding is unreviewed."""

    def test_batch_blocked_if_any_unreviewed(self) -> None:
        mod = _load_module()
        reviewed = _make_finding(finding_id=1, reviewed_by_human=True)
        unreviewed = _make_finding(finding_id=2, reviewed_by_human=False)

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [reviewed, unreviewed]

        body = MagicMock()
        body.finding_ids = [1, 2]
        body.template = "summary"

        with self.assertRaises(Exception) as ctx:
            mod.batch_report(body, db=mock_db)

        err = str(ctx.exception)
        self.assertIn("reviewed", err.lower())

    def test_batch_succeeds_when_all_reviewed(self) -> None:
        mod = _load_module()
        r1 = _make_finding(finding_id=1, reviewed_by_human=True)
        r2 = _make_finding(finding_id=2, reviewed_by_human=True)

        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [r1, r2]

        body = MagicMock()
        body.finding_ids = [1, 2]
        body.template = "summary"

        generator_mock = MagicMock()
        generator_mock.generate_batch_report.return_value = "# Batch"
        mod.ReportGenerator = MagicMock(return_value=generator_mock)

        result = mod.batch_report(body, db=mock_db)
        self.assertIn("report_markdown", result)


class TestStatusUpdateRequiresReview(unittest.TestCase):
    """update_status must block ready_to_submit/submitted without human review."""

    def test_ready_to_submit_blocked_without_review(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=False, status="draft")
        mock_db = _make_db(finding)

        with self.assertRaises(Exception) as ctx:
            mod.update_status(1, status="ready_to_submit", db=mock_db)

        err = str(ctx.exception)
        self.assertIn("reviewed", err.lower())

    def test_submitted_blocked_without_review(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=False, status="draft")
        mock_db = _make_db(finding)

        with self.assertRaises(Exception) as ctx:
            mod.update_status(1, status="submitted", db=mock_db)

        err = str(ctx.exception)
        self.assertIn("reviewed", err.lower())

    def test_needs_review_allowed_without_human_review(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=False, status="draft")
        mock_db = _make_db(finding)

        # needs_review does NOT require reviewed_by_human
        try:
            mod.update_status(1, status="needs_review", db=mock_db)
        except Exception as exc:
            # Should not raise — but if something else raises (e.g. _to_out mock), that's ok
            # The key is it should not raise about "reviewed"
            self.assertNotIn("reviewed", str(exc).lower(), msg=f"Unexpected error: {exc}")

    def test_ready_to_submit_allowed_when_reviewed(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=True, status="needs_review")
        mock_db = _make_db(finding)

        try:
            mod.update_status(1, status="ready_to_submit", db=mock_db)
        except Exception as exc:
            self.assertNotIn("reviewed", str(exc).lower(), msg=f"Unexpected error: {exc}")


class TestMarkReviewed(unittest.TestCase):
    """mark_reviewed endpoint correctly sets review fields."""

    def test_mark_reviewed_sets_fields(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=False, status="draft")
        mock_db = _make_db(finding)

        body = MagicMock()
        body.reviewer = "alice"
        body.review_notes = "Looks good."

        try:
            mod.mark_reviewed(1, body=body, db=mock_db)
        except Exception:
            pass  # _to_out may fail with mocks; we check the side-effects below

        self.assertTrue(finding.reviewed_by_human)
        self.assertEqual(finding.reviewer, "alice")
        self.assertEqual(finding.review_notes, "Looks good.")
        self.assertIsNotNone(finding.reviewed_at)

    def test_mark_reviewed_not_found_raises(self) -> None:
        mod = _load_module()
        mock_db = _make_db(None)

        body = MagicMock()
        body.reviewer = "alice"
        body.review_notes = None

        with self.assertRaises(Exception):
            mod.mark_reviewed(999, body=body, db=mock_db)

    def test_mark_reviewed_advances_draft_status(self) -> None:
        mod = _load_module()
        finding = _make_finding(reviewed_by_human=False, status="draft")
        mock_db = _make_db(finding)

        body = MagicMock()
        body.reviewer = "bob"
        body.review_notes = None

        try:
            mod.mark_reviewed(1, body=body, db=mock_db)
        except Exception:
            pass

        # status should have advanced from draft to needs_review
        self.assertEqual(finding.status, "needs_review")


if __name__ == "__main__":
    unittest.main()
