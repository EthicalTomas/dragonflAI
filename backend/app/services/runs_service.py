from sqlalchemy.orm import Session

from app.models.run import Run, RunStatus


def get_run_status(run_id: int, db: Session) -> RunStatus | None:
    run = db.query(Run).filter(Run.id == run_id).first()
    return run.status if run else None


def update_run_status(run_id: int, status: RunStatus, db: Session) -> None:
    run = db.query(Run).filter(Run.id == run_id).first()
    if run:
        run.status = status
        db.commit()
