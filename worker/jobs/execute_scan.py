import datetime
import json
import logging
import os
from pathlib import Path

from backend.app.core.config import settings
from backend.app.db.session import SessionLocal
from backend.app.models.scan import Scan, ScanStatus
from backend.app.scans.nuclei_parser import parse_nuclei_jsonl
from backend.app.scans.nuclei_runner import preflight, run_nuclei
from backend.app.scans.url_export import export_scan_urls
from backend.app.scope.parser import parse_scope_text
from backend.app.scope.validator import ScopeValidator

logger = logging.getLogger(__name__)

_ARTIFACTS_BASE = os.environ.get("SCAN_ARTIFACTS_DIR", "/tmp/dragonflai_scans")


def _build_scope_validator(db, target_id: int) -> ScopeValidator:
    """Load the target's program scope rules and return a configured ScopeValidator.

    This is the code-level guarantee that out-of-scope URLs never reach nuclei,
    even when scans are triggered via the API rather than the recon pipeline.
    """
    from backend.app.models.program import Program  # noqa: PLC0415
    from backend.app.models.target import Target  # noqa: PLC0415

    target = db.get(Target, target_id)
    if target is None:
        raise ValueError(f"Target {target_id} not found")
    scope_text = ""
    if target.program_id is not None:
        program = db.get(Program, target.program_id)
        scope_text = (program.scope_text or "") if program else ""
    return ScopeValidator(parse_scope_text(scope_text))


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    scan = None  # referenced in the except block before assignment may happen
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        # Honour the master kill-switch even for jobs already enqueued.
        if not settings.scan_enabled:
            raise RuntimeError(
                "execute_scan: scanning is disabled (SCAN_ENABLED=false). "
                "Set SCAN_ENABLED=true to allow nuclei scans."
            )

        scan.status = ScanStatus.RUNNING
        scan.updated_at = datetime.datetime.now(datetime.UTC)
        scan.log_text = (scan.log_text or "") + "[execute_scan] status -> running\n"
        db.commit()

        logger.info("execute_scan: scan_id=%d scanner=%s", scan_id, scan.scanner)

        artifacts_dir = str(Path(_ARTIFACTS_BASE) / str(scan_id))
        os.makedirs(artifacts_dir, exist_ok=True)

        # 1. Preflight checks
        scan.log_text = (scan.log_text or "") + "[execute_scan] running preflight checks\n"
        db.commit()
        config_meta = preflight()

        # 2. Build scope validator and export URLs (default-deny enforced in code)
        scan.log_text = (scan.log_text or "") + "[execute_scan] exporting URLs\n"
        db.commit()
        scope_validator = _build_scope_validator(db, scan.target_id)
        export_scan_urls(
            db,
            target_id=scan.target_id,
            scan_id=scan_id,
            artifacts_dir=artifacts_dir,
            scope_validator=scope_validator,
        )

        # 3. Persist config_json capturing the exact command config and template commit SHA
        config_data = {
            "scanner": "nuclei",
            "template_commit": config_meta.get("template_commit"),
            "templates_url": config_meta.get("templates_url"),
            "tags": config_meta.get("tags"),
            "etags": config_meta.get("etags"),
            "flags": config_meta.get("flags"),
            "artifacts_dir": artifacts_dir,
        }
        scan.config_json = json.dumps(config_data)
        db.commit()

        # 4. Run nuclei
        scan.log_text = (scan.log_text or "") + "[execute_scan] running nuclei\n"
        db.commit()
        jsonl_path = run_nuclei(artifacts_dir=artifacts_dir)

        # 5. Parse and store results
        scan.log_text = (scan.log_text or "") + "[execute_scan] parsing results\n"
        db.commit()
        result_count = parse_nuclei_jsonl(
            db,
            jsonl_path=jsonl_path,
            scan_id=scan_id,
            target_id=scan.target_id,
            run_id=scan.run_id,
        )

        scan.status = ScanStatus.SUCCEEDED
        scan.updated_at = datetime.datetime.now(datetime.UTC)
        scan.log_text = (scan.log_text or "") + f"[execute_scan] done: {result_count} findings\n"
        db.commit()

        logger.info(
            "execute_scan: scan_id=%d finished with status=%s findings=%d",
            scan_id,
            scan.status,
            result_count,
        )
    except Exception:
        logger.exception("execute_scan: crashed (scan_id=%d)", scan_id)
        try:
            if scan is not None:
                scan.status = ScanStatus.FAILED
                scan.updated_at = datetime.datetime.now(datetime.UTC)
                scan.log_text = (scan.log_text or "") + "[execute_scan] FAILED\n"
                db.commit()
        except Exception:
            logger.exception("execute_scan: failed to update scan status (scan_id=%d)", scan_id)
        raise
    finally:
        db.close()
