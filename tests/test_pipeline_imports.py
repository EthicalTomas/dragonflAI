"""Minimal tests for backend.app.runs.pipeline.

These tests verify that the module exposes the expected stdlib imports
(os, re, logging) and that the module-level helpers work correctly,
without requiring a live database or external tools.
"""

import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock


def _build_mock(name: str) -> types.ModuleType:
    """Return a MagicMock registered as *name* in sys.modules."""
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


# ---------------------------------------------------------------------------
# Patch all third-party / internal modules before importing pipeline
# ---------------------------------------------------------------------------
_MOCKED_MODULES = [
    "sqlalchemy",
    "sqlalchemy.orm",
    "backend",
    "backend.app",
    "backend.app.detection",
    "backend.app.detection.orchestrator",
    "backend.app.models",
    "backend.app.parsers",
    "backend.app.parsers.burp_parser",
    "backend.app.parsers.httpx_parser",
    "backend.app.parsers.nmap_parser",
    "backend.app.parsers.subfinder_parser",
    "backend.app.parsers.zap_parser",
    "backend.app.runs",
    "backend.app.runs.preflight",
    "backend.app.scope",
    "backend.app.scope.validator",
    "backend.app.services",
    "backend.app.services.asset_service",
    "backend.app.services.endpoint_service",
    "backend.app.services.runs_service",
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
        sys.modules[name] = _build_mock(name)


def tearDownModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        original = _original_modules.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


class TestPipelineImports(unittest.TestCase):
    """Verify that pipeline.py can be imported and exposes expected symbols."""

    @classmethod
    def setUpClass(cls) -> None:
        # Import (or reload) the module under test after mocks are in place.
        if "backend.app.runs.pipeline" in sys.modules:
            del sys.modules["backend.app.runs.pipeline"]
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "backend.app.runs.pipeline",
            "backend/app/runs/pipeline.py",
        )
        cls.pipeline = importlib.util.module_from_spec(spec)
        sys.modules["backend.app.runs.pipeline"] = cls.pipeline
        spec.loader.exec_module(cls.pipeline)

    def test_module_imports_os(self) -> None:
        import os

        self.assertIs(self.pipeline.os, os)

    def test_module_imports_re(self) -> None:
        import re

        self.assertIs(self.pipeline.re, re)

    def test_module_imports_logging(self) -> None:
        import logging

        self.assertIs(self.pipeline.logging, logging)

    def test_dnsx_ip_regex_matches_bracket(self) -> None:
        """_DNSX_IP_RE should extract the content of square-bracket tokens."""
        matches = self.pipeline._DNSX_IP_RE.findall("example.com [A] [1.2.3.4]")
        self.assertEqual(matches, ["A", "1.2.3.4"])

    def test_parse_dnsx_output_missing_file(self) -> None:
        """_parse_dnsx_output returns [] and logs a warning for missing files."""
        result = self.pipeline._parse_dnsx_output("/nonexistent/path/dnsx.txt")
        self.assertEqual(result, [])

    def test_parse_dnsx_output_parses_lines(self) -> None:
        """_parse_dnsx_output correctly parses valid dnsx output lines."""
        import os
        import tempfile

        content = "example.com [A] [1.2.3.4]\nsub.example.com [A] [5.6.7.8]\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as fh:
            fh.write(content)
            tmp_path = fh.name
        try:
            result = self.pipeline._parse_dnsx_output(tmp_path)
        finally:
            os.unlink(tmp_path)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["hostname"], "example.com")
        self.assertIn("1.2.3.4", result[0]["ips"])
        self.assertEqual(result[1]["hostname"], "sub.example.com")
        self.assertIn("5.6.7.8", result[1]["ips"])

    def test_recon_pipeline_class_exists(self) -> None:
        """ReconPipeline class should be present in the module."""
        self.assertTrue(hasattr(self.pipeline, "ReconPipeline"))

    def test_recon_pipeline_available_steps(self) -> None:
        """ReconPipeline.AVAILABLE_STEPS should list expected step names."""
        steps = self.pipeline.ReconPipeline.AVAILABLE_STEPS
        for expected in ("subfinder", "dnsx", "httpx", "nmap", "detect"):
            self.assertIn(expected, steps)


if __name__ == "__main__":
    unittest.main()
