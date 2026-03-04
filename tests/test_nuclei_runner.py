"""Tests for backend.app.scans.nuclei_runner.

Runs without Docker, docker compose, or external services by patching
subprocess and filesystem calls.
"""

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _build_mock(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


def _load_nuclei_runner():
    """Load nuclei_runner directly, avoiding the backend package hierarchy."""
    mod_name = "backend.app.scans.nuclei_runner"
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(
        mod_name,
        "backend/app/scans/nuclei_runner.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_runner = _load_nuclei_runner()


class TestReadLock(unittest.TestCase):
    """Tests for _read_lock()."""

    def test_parses_key_value_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "templates.lock"
            lock_file.write_text(
                "url=https://github.com/projectdiscovery/nuclei-templates\n"
                "commit=abc123def456\n",
                encoding="utf-8",
            )
            root = Path(tmpdir)
            # Temporarily point _TEMPLATES_LOCK to our temp file
            original = _runner._TEMPLATES_LOCK
            _runner._TEMPLATES_LOCK = str(lock_file.relative_to(root))
            try:
                result = _runner._read_lock(root)
            finally:
                _runner._TEMPLATES_LOCK = original

        self.assertEqual(result["commit"], "abc123def456")
        self.assertIn("nuclei-templates", result["url"])

    def test_raises_when_lock_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(RuntimeError) as ctx:
                _runner._read_lock(Path(tmpdir))
        self.assertIn("lock file not found", str(ctx.exception))


class TestResolveTemplatesCommit(unittest.TestCase):
    """Tests for _read_templates_commit()."""

    def test_returns_none_when_no_git_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _runner._read_templates_commit(Path(tmpdir))
        self.assertIsNone(result)

    def test_resolves_detached_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("deadbeefcafe\n", encoding="utf-8")
            result = _runner._read_templates_commit(Path(tmpdir))
        self.assertEqual(result, "deadbeefcafe")

    def test_resolves_symbolic_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            refs_dir = git_dir / "refs" / "heads"
            refs_dir.mkdir(parents=True)
            (refs_dir / "main").write_text("cafebabe1234\n", encoding="utf-8")
            result = _runner._read_templates_commit(Path(tmpdir))
        self.assertEqual(result, "cafebabe1234")


class TestPreflight(unittest.TestCase):
    """Tests for preflight()."""

    def _make_project(self, commit: str = "abc123") -> tempfile.TemporaryDirectory:
        """Create a minimal project-root-like temp directory."""
        tmpdir = tempfile.TemporaryDirectory()
        root = Path(tmpdir.name)
        # templates lock
        lock_dir = root / "infra" / "scanners"
        lock_dir.mkdir(parents=True)
        (lock_dir / "templates.lock").write_text(
            f"url=https://github.com/projectdiscovery/nuclei-templates\ncommit={commit}\n",
            encoding="utf-8",
        )
        # templates directory (not a git repo – no .git)
        templates_dir = lock_dir / "nuclei-templates"
        templates_dir.mkdir()
        return tmpdir

    def test_raises_when_docker_missing(self) -> None:
        with self._make_project() as tmpdir:
            with patch("shutil.which", return_value=None):
                with self.assertRaises(RuntimeError) as ctx:
                    _runner.preflight(project_root=tmpdir)
        self.assertIn("docker", str(ctx.exception))

    def test_raises_when_templates_dir_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # create lock but no templates dir
            lock_dir = root / "infra" / "scanners"
            lock_dir.mkdir(parents=True)
            (lock_dir / "templates.lock").write_text(
                "url=https://example.com\ncommit=abc123\n", encoding="utf-8"
            )
            with patch("shutil.which", return_value="/usr/bin/docker"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    with self.assertRaises(RuntimeError) as ctx:
                        _runner.preflight(project_root=tmpdir)
        self.assertIn("templates directory not found", str(ctx.exception))

    def test_raises_when_lock_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # templates dir exists but no lock
            templates_dir = root / "infra" / "scanners" / "nuclei-templates"
            templates_dir.mkdir(parents=True)
            with patch("shutil.which", return_value="/usr/bin/docker"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    with self.assertRaises(RuntimeError) as ctx:
                        _runner.preflight(project_root=tmpdir)
        self.assertIn("lock file not found", str(ctx.exception))

    def test_raises_when_commit_mismatch(self) -> None:
        with self._make_project(commit="expected_sha") as tmpdir:
            root = Path(tmpdir)
            # Make templates_dir a fake git repo with wrong commit
            git_dir = root / "infra" / "scanners" / "nuclei-templates" / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("wrong_sha\n", encoding="utf-8")
            with patch("shutil.which", return_value="/usr/bin/docker"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    with self.assertRaises(RuntimeError) as ctx:
                        _runner.preflight(project_root=tmpdir)
        self.assertIn("commit", str(ctx.exception).lower())

    def test_returns_config_metadata(self) -> None:
        with self._make_project(commit="abc123") as tmpdir:
            with patch("shutil.which", return_value="/usr/bin/docker"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    result = _runner.preflight(project_root=tmpdir)

        self.assertEqual(result["template_commit"], "abc123")
        self.assertIn("tags", result)
        self.assertIn("etags", result)
        self.assertIn("flags", result)
        self.assertEqual(result["flags"]["concurrency"], 10)
        self.assertEqual(result["flags"]["rate_limit"], 5)

    def test_tag_allowlist_and_denylist(self) -> None:
        with self._make_project() as tmpdir:
            with patch("shutil.which", return_value="/usr/bin/docker"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    result = _runner.preflight(project_root=tmpdir)

        for tag in ("cve", "misconfig", "exposure", "takeover"):
            self.assertIn(tag, result["tags"])
        for tag in ("dos", "fuzz", "intrusive", "bruteforce"):
            self.assertIn(tag, result["etags"])


class TestRunNuclei(unittest.TestCase):
    """Tests for run_nuclei()."""

    def test_returns_jsonl_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                result = _runner.run_nuclei(artifacts_dir=tmpdir)
        self.assertEqual(result.name, "nuclei.jsonl")
        self.assertEqual(result.parent, Path(tmpdir).resolve())

    def test_raises_on_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error output")
                with self.assertRaises(RuntimeError) as ctx:
                    _runner.run_nuclei(artifacts_dir=tmpdir)
        self.assertIn("exited with status 1", str(ctx.exception))

    def test_command_includes_safe_flags(self) -> None:
        """The subprocess command must contain the safe bug-bounty default flags."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                _runner.run_nuclei(artifacts_dir=tmpdir)

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        self.assertIn("-c", cmd_str)
        self.assertIn("-rl", cmd_str)
        self.assertIn("-timeout", cmd_str)
        self.assertIn("-retries", cmd_str)
        self.assertIn("cve,misconfig,exposure,takeover", cmd_str)
        self.assertIn("dos,fuzz,intrusive,bruteforce", cmd_str)

    def test_command_uses_work_volume(self) -> None:
        """/work volume is mounted from the artifacts dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                _runner.run_nuclei(artifacts_dir=tmpdir)

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        self.assertIn("/work", cmd_str)
        self.assertIn("nuclei.jsonl", cmd_str)

    def test_command_uses_templates_volume(self) -> None:
        """/templates is referenced in the nuclei command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                _runner.run_nuclei(artifacts_dir=tmpdir)

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        self.assertIn("/templates", cmd_str)


if __name__ == "__main__":
    unittest.main()
