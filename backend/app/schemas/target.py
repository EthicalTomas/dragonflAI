from datetime import datetime

from pydantic import BaseModel


class TargetCreate(BaseModel):
    program_id: int
    value: str
    kind: str


class TargetOut(TargetCreate):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}
