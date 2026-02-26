from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models import Program
from backend.app.schemas.program import ProgramCreate, ProgramOut

router = APIRouter()


@router.post("", response_model=ProgramOut, status_code=201)
def create_program(body: ProgramCreate, db: Session = Depends(get_db)):
    program = Program(**body.model_dump())
    db.add(program)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"A program named '{body.name}' already exists. Name must be unique.")
    db.refresh(program)
    return program


@router.get("", response_model=list[ProgramOut])
def list_programs(db: Session = Depends(get_db)):
    return db.query(Program).order_by(Program.id.desc()).all()
