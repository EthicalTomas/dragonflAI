import datetime

from sqlalchemy.orm import Session

from backend.app.models import Run, RunStatus


def append_log(db: Session, run: Run, line: str) -> None:
    run.log_text = (run.log_text or "") + line.strip() + "\n"


def set_status(db: Session, run: Run, status: str) -> None:
    run.status = status
    if status == RunStatus.RUNNING:
        run.started_at = datetime.datetime.utcnow()
    elif status in (RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED):
        run.finished_at = datetime.datetime.utcnow()


def set_progress(db: Session, run: Run, progress: int) -> None:
    run.progress = max(0, min(100, progress))
