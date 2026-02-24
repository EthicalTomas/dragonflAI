from __future__ import annotations

import logging

from app.db.session import SessionLocal
from app.runs.orchestrator import orchestrate_run

logger = logging.getLogger(__name__)


def execute_run(run_id: int) -> None:
    """RQ job entry point: run the recon pipeline for *run_id*."""
    logger.info("execute_run job started for run_id=%s", run_id)
    with SessionLocal() as db:
        orchestrate_run(run_id, db)
