from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.run import Run
from app.schemas.run import RunCreate, RunOut

router = APIRouter()


@router.post("", response_model=RunOut, status_code=201)
def create_run(payload: RunCreate, db: Session = Depends(get_db)):
    run = Run(**payload.model_dump())
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@router.get("", response_model=list[RunOut])
def list_runs(program_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(Run)
    if program_id is not None:
        q = q.filter(Run.program_id == program_id)
    return q.all()


@router.get("/{run_id}", response_model=RunOut)
def get_run(run_id: int, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run
