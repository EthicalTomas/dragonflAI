"""Run nuclei via docker compose and return the JSONL output path.

Preflight checks
----------------
1. ``docker compose`` binary is available.
2. Pinned templates directory exists at ``infra/scanners/nuclei-templates``.
3. ``infra/scanners/templates.lock`` is present and, when the templates dir
   is a git repo, the checked-out commit matches the locked SHA.

Safe bug-bounty scan defaults
------------------------------
- Concurrency:  ``-c 10``
- Rate-limit:   ``-rl 5``
- Timeout:      ``-timeout 10``
- Retries:      ``-retries 1``
- Tag allow:    ``cve,misconfig,exposure,takeover``
- Tag deny:     ``dos,fuzz,intrusive,bruteforce``
"""

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Paths relative to the project root
_COMPOSE_FILE = "infra/docker-compose.scanners.yml"
_TEMPLATES_DIR = "infra/scanners/nuclei-templates"
_TEMPLATES_LOCK = "infra/scanners/templates.lock"

_TAG_ALLOWLIST = "cve,misconfig,exposure,takeover"
_TAG_DENYLIST = "dos,fuzz,intrusive,bruteforce"


def _read_lock(root: Path) -> dict[str, str]:
    """Parse ``templates.lock`` into a plain dict."""
    lock_path = root / _TEMPLATES_LOCK
    if not lock_path.exists():
        raise RuntimeError(f"Preflight failed: templates lock file not found at {lock_path}")
    result: dict[str, str] = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def _read_templates_commit(templates_dir: Path) -> str | None:
    """Return the git commit SHA of *templates_dir*, or ``None`` if unresolvable."""
    git_head = templates_dir / ".git" / "HEAD"
    if not git_head.exists():
        return None
    head_content = git_head.read_text(encoding="utf-8").strip()
    if head_content.startswith("ref: "):
        ref_path = templates_dir / ".git" / head_content[5:]
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip()
        return None
    return head_content


def preflight(project_root: str | None = None) -> dict:
    """Run preflight checks and return config metadata.

    Parameters
    ----------
    project_root:
        Root of the project.  Defaults to ``Path.cwd()``.

    Returns
    -------
    dict
        Metadata captured for ``Scan.config_json``, including the template
        commit SHA and scan flags.

    Raises
    ------
    RuntimeError
        If any preflight check fails.
    """
    root = Path(project_root) if project_root else Path.cwd()

    # 1. docker compose available
    if shutil.which("docker") is None:
        raise RuntimeError("Preflight failed: 'docker' binary not found in PATH")
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Preflight failed: 'docker compose' not available: {exc}") from exc

    # 2. Pinned templates directory exists
    templates_dir = root / _TEMPLATES_DIR
    if not templates_dir.is_dir():
        raise RuntimeError(
            f"Preflight failed: nuclei templates directory not found at {templates_dir}. "
            "Clone nuclei-templates to infra/scanners/nuclei-templates."
        )

    # 3. Lock file present and commit matches (when verifiable)
    lock = _read_lock(root)
    expected_commit = lock.get("commit", "")
    actual_commit = _read_templates_commit(templates_dir)

    if actual_commit is not None and expected_commit and actual_commit != expected_commit:
        raise RuntimeError(
            f"Preflight failed: templates directory is at commit {actual_commit!r} "
            f"but lock expects {expected_commit!r}. "
            "Update infra/scanners/nuclei-templates to the pinned commit."
        )
    if actual_commit is None:
        logger.warning(
            "Templates directory %s is not a git repo; skipping commit SHA verification",
            templates_dir,
        )

    return {
        "template_commit": expected_commit,
        "templates_url": lock.get("url", ""),
        "tags": _TAG_ALLOWLIST,
        "etags": _TAG_DENYLIST,
        "flags": {
            "concurrency": 10,
            "rate_limit": 5,
            "timeout": 10,
            "retries": 1,
        },
    }


def run_nuclei(artifacts_dir: str, project_root: str | None = None) -> Path:
    """Run nuclei via docker compose and return the path to the JSONL output.

    Parameters
    ----------
    artifacts_dir:
        Directory that already contains ``urls.txt``.  Nuclei's JSONL output
        is written to ``<artifacts_dir>/nuclei.jsonl``.
    project_root:
        Root of the project.  Defaults to ``Path.cwd()``.

    Returns
    -------
    Path
        Absolute path to ``nuclei.jsonl`` inside *artifacts_dir*.

    Raises
    ------
    RuntimeError
        If nuclei exits with a non-zero return code.
    """
    root = Path(project_root) if project_root else Path.cwd()
    artifacts = Path(artifacts_dir).resolve()
    compose_file = (root / _COMPOSE_FILE).resolve()

    cmd = [
        "docker", "compose",
        "-f", str(compose_file),
        "run", "--rm",
        "-v", f"{artifacts}:/work",
        "nuclei",
        "-list", "/work/urls.txt",
        "-t", "/templates",
        "-c", "10",
        "-rl", "5",
        "-timeout", "10",
        "-retries", "1",
        "-tags", _TAG_ALLOWLIST,
        "-etags", _TAG_DENYLIST,
        "-je", "/work/nuclei.jsonl",
        "-silent",
        "-no-color",
    ]

    logger.info("run_nuclei: %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(root),
    )

    if result.stdout:
        logger.info("nuclei stdout: %s", result.stdout[:2000])
    if result.stderr:
        logger.info("nuclei stderr: %s", result.stderr[:2000])

    if result.returncode != 0:
        raise RuntimeError(
            f"nuclei exited with status {result.returncode}. "
            f"stderr: {result.stderr[:500]}"
        )

    return artifacts / "nuclei.jsonl"
