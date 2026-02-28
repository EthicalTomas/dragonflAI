import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models import Run, RunStatus, Target
from backend.app.runs.differ import RunDiffer

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/runs/{run_id}")
def get_run_diff(run_id: int, db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    previous_run = RunDiffer.get_previous_run(db, run)
    if previous_run is None:
        logger.info("No previous run found for run_id=%s", run_id)
        return {"message": "No previous run found. This is the first run.", "diff": None}

    logger.info("Diffing run_id=%s against previous run_id=%s", run_id, previous_run.id)
    return RunDiffer.diff_full(db, previous_run, run)


@router.get("/runs/{run_id_a}/compare/{run_id_b}")
def compare_runs(run_id_a: int, run_id_b: int, db: Session = Depends(get_db)):
    run_a = db.get(Run, run_id_a)
    if not run_a:
        raise HTTPException(status_code=404, detail=f"Run {run_id_a} not found")

    run_b = db.get(Run, run_id_b)
    if not run_b:
        raise HTTPException(status_code=404, detail=f"Run {run_id_b} not found")

    if run_a.target_id != run_b.target_id:
        raise HTTPException(status_code=400, detail="Runs belong to different targets")

    logger.info("Comparing run_id_a=%s and run_id_b=%s", run_id_a, run_id_b)
    return RunDiffer.diff_full(db, run_a, run_b)


@router.get("/targets/{target_id}/latest")
def get_latest_target_diff(target_id: int, db: Session = Depends(get_db)):
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    recent_runs = (
        db.query(Run)
        .filter(Run.target_id == target_id, Run.status == RunStatus.SUCCEEDED)
        .order_by(Run.id.desc())
        .limit(2)
        .all()
    )

    if len(recent_runs) < 2:
        message = (
            "No succeeded runs found for this target."
            if len(recent_runs) == 0
            else "Only one succeeded run found. Need at least two to diff."
        )
        logger.info("Insufficient runs for target_id=%s: %s", target_id, message)
        return {"message": message, "diff": None}

    run_b, run_a = recent_runs[0], recent_runs[1]
    logger.info("Diffing latest runs for target_id=%s: run_a=%s run_b=%s", target_id, run_a.id, run_b.id)
    return RunDiffer.diff_full(db, run_a, run_b)
