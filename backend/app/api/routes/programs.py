from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.program import Program
from app.schemas.program import ProgramCreate, ProgramOut

router = APIRouter()


@router.post("", response_model=ProgramOut, status_code=201)
def create_program(payload: ProgramCreate, db: Session = Depends(get_db)):
    program = Program(**payload.model_dump())
    db.add(program)
    db.commit()
    db.refresh(program)
    return program


@router.get("", response_model=list[ProgramOut])
def list_programs(db: Session = Depends(get_db)):
    return db.query(Program).all()


@router.get("/{program_id}", response_model=ProgramOut)
def get_program(program_id: int, db: Session = Depends(get_db)):
    program = db.query(Program).filter(Program.id == program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    return program
