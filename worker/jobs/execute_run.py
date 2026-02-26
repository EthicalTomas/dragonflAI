import logging
import time
import traceback

from backend.app.db.session import SessionLocal
from backend.app.models import Run, RunStatus
from backend.app.services.runs_service import append_log, set_progress, set_status

logger = logging.getLogger(__name__)


def execute_run(run_id: int) -> None:
    db = SessionLocal()
    run = None
    try:
        run = db.get(Run, run_id)
        if run is None:
            logger.warning("execute_run: run_id=%d not found", run_id)
            return

        set_status(db, run, RunStatus.RUNNING)
        append_log(db, run, "Starting pipeline...")
        db.commit()

        steps = ["Collecting targets", "Processing data", "Finalizing results"]
        for i, step_name in enumerate(steps, start=1):
            append_log(db, run, f"Step {i}/3: {step_name}")
            set_progress(db, run, int(i / 3 * 100))
            db.commit()
            time.sleep(2)

        append_log(db, run, "Pipeline complete.")
        set_progress(db, run, 100)
        set_status(db, run, RunStatus.SUCCEEDED)
        db.commit()

    except Exception:
        if run is not None:
            append_log(db, run, traceback.format_exc())
            set_status(db, run, RunStatus.FAILED)
            db.commit()
        else:
            logger.exception("execute_run: unhandled error before run was loaded (run_id=%d)", run_id)

    finally:
        db.close()
