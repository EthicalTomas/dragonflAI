import json

from fastapi import APIRouter, Depends, HTTPException
from redis import Redis
from rq import Queue
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models import Run, Target
from backend.app.schemas.run import RunCreate, RunOut

router = APIRouter()


@router.post("", response_model=RunOut, status_code=201)
def create_run(body: RunCreate, db: Session = Depends(get_db)):
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    run = Run(
        target_id=body.target_id,
        status="queued",
        progress=0,
        config_json=json.dumps({"modules": body.modules, "config": body.config}),
        log_text="",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue("recon", connection=redis_conn)
    q.enqueue("worker.jobs.execute_run.execute_run", run.id)
    return run


@router.get("", response_model=list[RunOut])
def list_runs(db: Session = Depends(get_db)):
    return db.query(Run).order_by(Run.id.desc()).all()


@router.get("/{run_id}", response_model=RunOut)
def get_run(run_id: int, db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run
