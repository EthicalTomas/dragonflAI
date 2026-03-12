"""RQ worker job: execute a verification task.

Follows the same pattern as execute_run / execute_scan:
- Opens a DB session with SessionLocal()
- Always closes the session in a finally block
- Catches exceptions only to log them, then re-raises so RQ marks the job
  as failed.
"""

import datetime
import json
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from backend.app.db.session import SessionLocal
from backend.app.models.finding import Finding
from backend.app.models.target import Target
from backend.app.models.verification import Verification, VerificationStatus
from backend.app.scope.parser import parse_scope_text
from backend.app.scope.validator import ScopeValidator, ScopeViolationError

logger = logging.getLogger(__name__)

_ARTIFACTS_BASE = os.environ.get("VERIFICATION_ARTIFACTS_DIR", "/tmp/dragonflai_verify")

_SUPPORTED_METHODS = {"http_replay", "dns_recheck", "screenshot"}


def _host_from_url(url: str) -> str:
    """Extract the host component from a URL or return the string as-is."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def _run_verifier(method: str, target_value: str, finding: Finding | None) -> dict[str, Any]:
    """Dispatch to the appropriate verifier and return a result dict."""
    if method == "http_replay":
        from backend.app.verify.vuln_router import VulnRouter  # noqa: PLC0415

        url = finding.url if finding and finding.url else target_value
        router = VulnRouter()
        result = router.route(
            url,
            vulnerability_type=finding.vulnerability_type if finding else None,
            title=finding.title if finding else None,
        )

    elif method == "dns_recheck":
        from backend.app.verify.dns_recheck import DnsRecheckVerifier  # noqa: PLC0415

        host = (
            _host_from_url(finding.url)
            if finding and finding.url
            else target_value
        )
        verifier = DnsRecheckVerifier()
        result = verifier.verify(host)

    elif method == "screenshot":
        from backend.app.verify.screenshot import ScreenshotVerifier  # noqa: PLC0415

        url = (finding.url if finding and finding.url else target_value)
        verifier = ScreenshotVerifier()
        result = verifier.verify(url)

    else:
        raise ValueError(f"Unsupported verification method: {method!r}")

    return {"status": result.status, "evidence": result.evidence, "notes": result.notes}


def execute_verification(verification_id: int) -> None:
    """Execute a queued verification job.

    Parameters
    ----------
    verification_id:
        Primary key of the :class:`Verification` record to process.
    """
    db = SessionLocal()
    verification = None
    try:
        verification = db.get(Verification, verification_id)
        if verification is None:
            raise ValueError(f"Verification {verification_id} not found")

        # --- Mark as running ---
        verification.status = VerificationStatus.RUNNING
        verification.updated_at = datetime.datetime.now(datetime.UTC)
        verification.log_text = (verification.log_text or "") + "[execute_verification] status -> running\n"
        db.commit()

        logger.info(
            "execute_verification: id=%d method=%s target_id=%d",
            verification_id,
            verification.method,
            verification.target_id,
        )

        # --- Scope check ---
        target = db.get(Target, verification.target_id)
        if target is None:
            raise ValueError(f"Target {verification.target_id} not found")

        scope_text = ""
        if target.program_id is not None:
            from backend.app.models.program import Program  # noqa: PLC0415

            program = db.get(Program, target.program_id)
            scope_text = (program.scope_text or "") if program else ""

        scope_rules = parse_scope_text(scope_text)
        validator = ScopeValidator(scope_rules)

        # Determine the host to scope-check from the associated finding or target roots
        finding: Finding | None = None
        if verification.finding_id is not None:
            finding = db.get(Finding, verification.finding_id)

        if finding and finding.url:
            check_host = _host_from_url(finding.url)
        elif target.roots_json:
            import json as _json  # noqa: PLC0415

            roots = _json.loads(target.roots_json or "[]")
            check_host = roots[0] if roots else target.name
        else:
            check_host = target.name

        try:
            validator.check_or_raise(check_host)
        except ScopeViolationError as exc:
            logger.warning("execute_verification: scope violation (id=%d): %s", verification_id, exc)
            verification.status = VerificationStatus.FAILED
            verification.updated_at = datetime.datetime.now(datetime.UTC)
            verification.log_text = (
                (verification.log_text or "") + f"[execute_verification] SCOPE VIOLATION: {exc}\n"
            )
            db.commit()
            raise

        # --- Run the verifier ---
        verification.log_text = (
            (verification.log_text or "") + f"[execute_verification] running {verification.method}\n"
        )
        db.commit()

        result = _run_verifier(verification.method, target.name, finding)

        # --- Write evidence artifacts ---
        artifacts_dir = Path(_ARTIFACTS_BASE) / str(verification.target_id)
        if verification.run_id:
            artifacts_dir = artifacts_dir / str(verification.run_id)
        artifacts_dir = artifacts_dir / "verify" / str(verification_id)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        evidence = result.get("evidence", {})

        # Write request/response artifacts if present
        for key, filename in (("request", "request.txt"), ("response", "response.txt")):
            if key in evidence:
                (artifacts_dir / filename).write_text(str(evidence[key]), encoding="utf-8")

        # Write meta.json
        meta = {
            "verification_id": verification_id,
            "method": verification.method,
            "status": result["status"],
            "notes": result.get("notes", ""),
        }
        (artifacts_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        # Augment evidence with artifact paths
        evidence["artifacts_dir"] = str(artifacts_dir)
        result["evidence"] = evidence

        # --- Persist result ---
        verification.status = result["status"]
        verification.evidence_json = json.dumps(result["evidence"])
        verification.updated_at = datetime.datetime.now(datetime.UTC)
        verification.log_text = (
            (verification.log_text or "")
            + f"[execute_verification] done: {result['status']}\n"
            + (result.get("notes", "") or "")
            + "\n"
        )
        db.commit()

        logger.info(
            "execute_verification: id=%d finished status=%s",
            verification_id,
            result["status"],
        )

    except Exception:
        logger.exception("execute_verification: crashed (verification_id=%d)", verification_id)
        try:
            if verification is not None:
                verification.status = VerificationStatus.FAILED
                verification.updated_at = datetime.datetime.now(datetime.UTC)
                verification.log_text = (
                    (verification.log_text or "") + "[execute_verification] FAILED\n"
                )
                db.commit()
        except Exception:
            logger.exception(
                "execute_verification: failed to update status (id=%d)", verification_id
            )
        raise
    finally:
        db.close()
