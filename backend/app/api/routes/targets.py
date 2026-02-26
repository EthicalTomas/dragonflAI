import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models import Program, Target
from backend.app.schemas.target import TargetCreate, TargetOut

router = APIRouter()


def _to_out(target: Target) -> TargetOut:
    return TargetOut(
        id=target.id,
        program_id=target.program_id,
        name=target.name,
        roots=json.loads(target.roots_json or "[]"),
        tags=json.loads(target.tags_json or "[]"),
        created_at=target.created_at,
    )


@router.post("", response_model=TargetOut, status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db)):
    if not db.get(Program, body.program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    target = Target(
        program_id=body.program_id,
        name=body.name,
        roots_json=json.dumps(body.roots),
        tags_json=json.dumps(body.tags),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return _to_out(target)


@router.get("", response_model=list[TargetOut])
def list_targets(program_id: int | None = None, db: Session = Depends(get_db)):
    if program_id is not None and not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    query = db.query(Target)
    if program_id is not None:
        query = query.filter(Target.program_id == program_id)
    targets = query.order_by(Target.id.desc()).all()
    return [_to_out(t) for t in targets]
