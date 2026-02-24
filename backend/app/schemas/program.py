from datetime import datetime

from pydantic import BaseModel


class ProgramCreate(BaseModel):
    name: str
    platform: str | None = None
    scope_raw: str | None = None


class ProgramOut(ProgramCreate):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}
