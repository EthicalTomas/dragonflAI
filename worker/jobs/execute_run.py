import logging

from backend.app.db.session import SessionLocal
from backend.app.runs.orchestrator import RunOrchestrator

logger = logging.getLogger(__name__)


def execute_run(run_id: int) -> None:
    db = SessionLocal()
    try:
        orchestrator = RunOrchestrator(run_id, db)
        orchestrator.execute()
    except Exception:
        logger.exception("execute_run: orchestrator crashed (run_id=%d)", run_id)
    finally:
        db.close()
