"""Tests for backend.app.runs.preflight.

These tests load preflight.py directly via importlib to avoid triggering the
backend package hierarchy (which requires sqlalchemy and other dependencies).
"""

import importlib.util
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


def _load_preflight():
    """Load preflight.py directly, registering it in sys.modules."""
    module_name = "backend.app.runs.preflight"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(
        module_name,
        "backend/app/runs/preflight.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


_preflight = _load_preflight()
check_binaries = _preflight.check_binaries
_BINARY_INFO = _preflight._BINARY_INFO


class TestCheckBinaries(unittest.TestCase):
    """Tests for check_binaries()."""

    def test_all_present_does_not_raise(self) -> None:
        """check_binaries should succeed when every binary is found."""
        with patch("shutil.which", return_value="/usr/bin/tool"):
            check_binaries(["subfinder", "dnsx", "httpx", "nmap"])

    def test_missing_binary_raises_runtime_error(self) -> None:
        """check_binaries raises RuntimeError when a binary is missing."""
        def fake_which(binary: str):
            return None if binary == "subfinder" else "/usr/bin/" + binary

        with patch("shutil.which", side_effect=fake_which):
            with self.assertRaises(RuntimeError) as ctx:
                check_binaries(["subfinder", "nmap"])

        error_msg = str(ctx.exception)
        self.assertIn("subfinder", error_msg)
        self.assertIn("Preflight check failed", error_msg)
        self.assertIn("Install:", error_msg)

    def test_error_message_contains_install_instructions(self) -> None:
        """Missing binary error includes install steps for all missing tools."""
        with patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                check_binaries(["subfinder", "nmap"])

        msg = str(ctx.exception)
        self.assertIn("subfinder", msg)
        self.assertIn("nmap", msg)
        self.assertIn("go install", msg)
        self.assertIn("apt install nmap", msg)

    def test_error_message_references_docs(self) -> None:
        """Error message should point to setup docs."""
        with patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                check_binaries(["nmap"])

        self.assertIn("docs/setup.md", str(ctx.exception))

    def test_non_binary_steps_are_skipped(self) -> None:
        """Steps without binaries (import_burp, import_zap, detect) are ignored."""
        with patch("shutil.which", return_value=None) as mock_which:
            check_binaries(["import_burp", "import_zap", "detect"])
        mock_which.assert_not_called()

    def test_empty_modules_does_not_raise(self) -> None:
        """check_binaries with an empty list is a no-op."""
        check_binaries([])

    def test_binary_info_covers_expected_tools(self) -> None:
        """_BINARY_INFO should cover the four core recon tools."""
        for tool in ("subfinder", "dnsx", "httpx", "nmap"):
            self.assertIn(tool, _BINARY_INFO)
            self.assertIn("binary", _BINARY_INFO[tool])
            self.assertIn("install", _BINARY_INFO[tool])

    def test_only_missing_binary_mentioned_in_error(self) -> None:
        """Only the actually missing binary appears in the error; present ones do not."""
        def fake_which(binary: str):
            return "/usr/bin/nmap" if binary == "nmap" else None

        with patch("shutil.which", side_effect=fake_which):
            with self.assertRaises(RuntimeError) as ctx:
                check_binaries(["subfinder", "nmap"])

        msg = str(ctx.exception)
        self.assertIn("subfinder", msg)
        lines = msg.split("\n")
        missing_lines = [line for line in lines if line.strip().startswith("- ")]
        self.assertEqual(len(missing_lines), 1)
        self.assertIn("subfinder", missing_lines[0])


if __name__ == "__main__":
    unittest.main()
