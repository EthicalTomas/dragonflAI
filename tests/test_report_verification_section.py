"""Tests for verification-evidence section in ReportGenerator.

Covers:
- _build_verification_section returns empty string when no verification exists
- _build_verification_section returns a formatted section when a verification exists
- _build_verification_section fails gracefully on DB errors (returns empty string)
- generate_report without db parameter is unchanged (backwards-compatible)
- generate_report with db parameter appends the section when a verification exists
- generate_report with db parameter does not append section when no verification exists
- Evidence key formatting: status_code, location+canary, final_url, error, artifacts_dir
- vuln_router is included in method string when present
"""

import datetime
import json
import sys
import types
import unittest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Stub out heavy dependencies so the module loads in isolation
# ---------------------------------------------------------------------------

def _stub(name: str) -> types.ModuleType:
    mod = MagicMock(spec=types.ModuleType(name))
    mod.__name__ = name
    mod.__spec__ = None
    return mod


_STUBS = [
    "backend",
    "backend.app",
    "backend.app.llm",
    "backend.app.llm.base",
    "backend.app.llm.null_provider",
    "backend.app.models",
    "backend.app.models.finding",
    "backend.app.models.verification",
    "backend.app.reports",
    "backend.app.reports.templates",
]

_originals: dict = {}


def setUpModule() -> None:  # noqa: N802
    for name in _STUBS:
        _originals[name] = sys.modules.get(name)
        sys.modules[name] = _stub(name)

    # NullLLMProvider – must be a distinct class so isinstance checks work
    class _NullLLM:
        def generate(self, prompt: str) -> str:  # pragma: no cover
            return prompt

    null_mod = sys.modules["backend.app.llm.null_provider"]
    null_mod.NullLLMProvider = _NullLLM

    # LLMProvider base
    class _LLMBase:
        pass

    llm_base_mod = sys.modules["backend.app.llm.base"]
    llm_base_mod.LLMProvider = _LLMBase

    # Finding stub
    class _Finding:
        id = 1
        title = "Test Finding"
        severity = "high"
        vulnerability_type = "XSS"
        status = "open"
        url = "https://example.com"
        parameter = "q"
        description = "A test finding."
        steps_to_reproduce = "1. Do something."
        impact = "High impact."
        remediation = "Fix it."
        request_response = "GET / HTTP/1.1"
        cvss_score = 7.5
        cvss_vector = "AV:N/AC:L"
        created_at = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        evidence_paths_json = "[]"
        references_json = "[]"
        report_markdown = None

    sys.modules["backend.app.models.finding"].Finding = _Finding

    # Verification model stub
    class _Verification:
        finding_id = MagicMock()
        status = None
        method = None
        evidence_json = None
        updated_at = None
        created_at = None

    # Make id a MagicMock so Verification.id.desc() works in queries
    _Verification.id = MagicMock()

    verification_mod = sys.modules["backend.app.models.verification"]
    verification_mod.Verification = _Verification

    # templates stub
    def _get_template(name: str) -> str:
        templates = {
            "full": (
                "# {title}\n\n{severity}\n\n{vulnerability_type}\n\n{status}\n\n"
                "{url}\n\n{parameter}\n\n{method}\n\n{description}\n\n"
                "{steps_to_reproduce}\n\n{impact}\n\n{remediation}\n\n"
                "{request_response}\n\n{cvss_score}\n\n{cvss_vector}\n\n"
                "{created_at}\n\n{evidence_list}\n\n{references_list}"
            ),
            "platform": (
                "## Summary\n{description}\n\n"
                "## Steps to Reproduce\n{steps_to_reproduce}\n\n"
                "## Supporting Material/References\n{evidence_list}\n{references_list}\n\n"
                "## Impact\n{impact}\n\n"
                "## Suggested Remediation\n{remediation}"
            ),
            "summary": "## {title}\n{severity} | {vulnerability_type}\n{description}\n{impact}",
        }
        if name not in templates:
            raise ValueError(f"Unknown template name: {name!r}")
        return templates[name]

    sys.modules["backend.app.reports.templates"].get_template = _get_template


def tearDownModule() -> None:  # noqa: N802
    for name in _STUBS:
        original = _originals.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    # Unload the module under test so other tests get a fresh import
    sys.modules.pop("backend.app.reports.generator", None)


def _load_generator():
    sys.modules.pop("backend.app.reports.generator", None)
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "backend.app.reports.generator",
        "backend/app/reports/generator.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["backend.app.reports.generator"] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_verification(
    *,
    finding_id: int = 1,
    status: str = "confirmed",
    method: str = "http_replay",
    evidence: dict | None = None,
    updated_at: datetime.datetime | None = None,
    created_at: datetime.datetime | None = None,
) -> MagicMock:
    v = MagicMock()
    v.id = 42
    v.finding_id = finding_id
    v.status = status
    v.method = method
    v.evidence_json = json.dumps(evidence) if evidence is not None else None
    v.updated_at = updated_at
    v.created_at = created_at or datetime.datetime(2026, 3, 12, 17, 22, 11, tzinfo=datetime.timezone.utc)
    return v


def _make_db(verification_result=None) -> MagicMock:
    """Build a mock DB session whose .query(...).filter(...).order_by(...).first() returns verification_result."""
    mock_db = MagicMock()
    chain = mock_db.query.return_value.filter.return_value.order_by.return_value
    chain.first.return_value = verification_result
    return mock_db


# ===========================================================================


class TestBuildVerificationSection(unittest.TestCase):
    """Unit tests for the _build_verification_section helper."""

    def setUp(self):
        self.mod = _load_generator()

    def test_returns_empty_string_when_no_verification(self):
        db = _make_db(None)
        result = self.mod._build_verification_section(1, db)
        self.assertEqual(result, "")

    def test_returns_empty_string_on_db_error(self):
        db = MagicMock()
        db.query.side_effect = RuntimeError("table not found")
        result = self.mod._build_verification_section(1, db)
        self.assertEqual(result, "")

    def test_contains_verdict_and_method(self):
        v = _make_verification(status="confirmed", method="http_replay")
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("confirmed", section)
        self.assertIn("http_replay", section)

    def test_contains_timestamp_from_updated_at(self):
        ts = datetime.datetime(2026, 3, 12, 17, 22, 11, tzinfo=datetime.timezone.utc)
        v = _make_verification(updated_at=ts)
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("2026-03-12 17:22:11 UTC", section)

    def test_contains_timestamp_from_created_at_when_no_updated_at(self):
        ts = datetime.datetime(2026, 3, 10, 9, 0, 0, tzinfo=datetime.timezone.utc)
        v = _make_verification(updated_at=None, created_at=ts)
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("2026-03-10 09:00:00 UTC", section)

    def test_vuln_router_appended_to_method(self):
        v = _make_verification(evidence={"vuln_router": "open_redirect"})
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("VulnRouter: open_redirect", section)

    def test_no_vuln_router_when_absent(self):
        v = _make_verification(evidence={})
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertNotIn("VulnRouter", section)

    def test_status_code_in_key_evidence(self):
        v = _make_verification(evidence={"status_code": 302})
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("302", section)
        self.assertIn("Key evidence:", section)

    def test_location_with_canary_matched(self):
        evidence = {
            "status_code": 302,
            "location": "https://dragonflai-verify.invalid/",
            "canary_matched": True,
        }
        v = _make_verification(evidence=evidence)
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("canary matched", section)
        self.assertIn("https://dragonflai-verify.invalid/", section)

    def test_location_without_canary_matched(self):
        evidence = {
            "location": "https://example.com/",
            "canary_matched": False,
        }
        v = _make_verification(evidence=evidence)
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("https://example.com/", section)
        self.assertNotIn("canary matched", section)

    def test_final_url_included(self):
        v = _make_verification(evidence={"final_url": "https://target.tld/redirect"})
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("https://target.tld/redirect", section)

    def test_artifacts_dir_included(self):
        v = _make_verification(evidence={"artifacts_dir": "/tmp/dragonflai_verify/"})
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertIn("Artifacts:", section)
        self.assertIn("/tmp/dragonflai_verify/", section)

    def test_no_artifacts_section_when_absent(self):
        v = _make_verification(evidence={})
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertNotIn("Artifacts:", section)

    def test_invalid_evidence_json_does_not_raise(self):
        v = _make_verification()
        v.evidence_json = "not-valid-json"
        db = _make_db(v)
        # Should not raise; returns a section without evidence details
        section = self.mod._build_verification_section(1, db)
        self.assertIn("Verification Evidence", section)

    def test_section_header(self):
        v = _make_verification()
        db = _make_db(v)
        section = self.mod._build_verification_section(1, db)
        self.assertTrue(section.startswith("## Verification Evidence (Automated)"))


class TestGenerateReportWithVerification(unittest.TestCase):
    """Integration tests: generate_report() with and without db."""

    def setUp(self):
        self.mod = _load_generator()
        self.NullLLM = sys.modules["backend.app.llm.null_provider"].NullLLMProvider
        self.Finding = sys.modules["backend.app.models.finding"].Finding

    def _make_finding(self):
        f = MagicMock(spec=self.Finding)
        f.id = 7
        f.title = "Open Redirect"
        f.severity = "medium"
        f.vulnerability_type = "Open Redirect"
        f.status = "confirmed"
        f.url = "https://target.tld/redirect"
        f.parameter = "next"
        f.description = "Open redirect via next parameter."
        f.steps_to_reproduce = "1. Navigate to /redirect?next=evil"
        f.impact = "Phishing."
        f.remediation = "Validate redirect destination."
        f.request_response = "GET /redirect?next=evil HTTP/1.1"
        f.cvss_score = 5.4
        f.cvss_vector = "AV:N/AC:L"
        f.created_at = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        f.evidence_paths_json = "[]"
        f.references_json = "[]"
        return f

    def test_no_db_produces_same_result_as_before(self):
        generator = self.mod.ReportGenerator(self.NullLLM())
        finding = self._make_finding()
        report = generator.generate_report(finding, template_name="full")
        self.assertNotIn("Verification Evidence", report)

    def test_with_db_no_verification_unchanged(self):
        generator = self.mod.ReportGenerator(self.NullLLM())
        finding = self._make_finding()
        db = _make_db(None)
        report = generator.generate_report(finding, template_name="full", db=db)
        self.assertNotIn("Verification Evidence", report)

    def test_with_db_and_verification_appends_section(self):
        generator = self.mod.ReportGenerator(self.NullLLM())
        finding = self._make_finding()
        v = _make_verification(
            status="confirmed",
            method="http_replay",
            evidence={
                "status_code": 302,
                "location": "https://dragonflai-verify.invalid/",
                "canary_matched": True,
                "final_url": "https://target.tld/redirect?next=evil",
                "artifacts_dir": "/tmp/dragonflai_verify/",
                "vuln_router": "open_redirect",
            },
            updated_at=datetime.datetime(2026, 3, 12, 17, 22, 11, tzinfo=datetime.timezone.utc),
        )
        db = _make_db(v)
        report = generator.generate_report(finding, template_name="platform", db=db)
        self.assertIn("## Verification Evidence (Automated)", report)
        self.assertIn("confirmed", report)
        self.assertIn("VulnRouter: open_redirect", report)
        self.assertIn("2026-03-12 17:22:11 UTC", report)
        self.assertIn("canary matched", report)
        self.assertIn("/tmp/dragonflai_verify/", report)

    def test_verification_section_separated_by_divider(self):
        generator = self.mod.ReportGenerator(self.NullLLM())
        finding = self._make_finding()
        v = _make_verification(status="unconfirmed")
        db = _make_db(v)
        report = generator.generate_report(finding, template_name="summary", db=db)
        self.assertIn("---", report)
        idx_divider = report.rindex("---")
        idx_section = report.index("## Verification Evidence")
        self.assertLess(idx_divider, idx_section)

    def test_finding_with_none_id_skips_verification(self):
        generator = self.mod.ReportGenerator(self.NullLLM())
        finding = self._make_finding()
        finding.id = None
        db = _make_db(_make_verification())
        report = generator.generate_report(finding, template_name="summary", db=db)
        self.assertNotIn("Verification Evidence", report)


if __name__ == "__main__":
    unittest.main()
