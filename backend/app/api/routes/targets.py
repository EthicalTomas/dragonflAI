from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetOut

router = APIRouter()


@router.post("", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    target = Target(**payload.model_dump())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=list[TargetOut])
def list_targets(program_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(Target)
    if program_id is not None:
        q = q.filter(Target.program_id == program_id)
    return q.all()


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target
