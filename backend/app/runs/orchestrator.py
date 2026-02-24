from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.run import Run, RunStatus
from app.services.runs_service import update_run_status

logger = logging.getLogger(__name__)


def orchestrate_run(run_id: int, db: Session) -> None:
    """Execute the recon pipeline for a given run."""
    logger.info("Starting run %s", run_id)
    update_run_status(run_id, RunStatus.running, db)
    try:
        # Tool execution steps are enqueued here in the full implementation.
        logger.info("Run %s completed", run_id)
        update_run_status(run_id, RunStatus.completed, db)
    except Exception:
        logger.exception("Run %s failed", run_id)
        update_run_status(run_id, RunStatus.failed, db)
        raise
