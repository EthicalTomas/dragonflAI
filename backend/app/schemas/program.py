from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProgramCreate(BaseModel):
    name: str
    platform: str | None = None
    scope_text: str | None = None
    notes: str | None = None


class ProgramOut(BaseModel):
    id: int
    name: str
    platform: str | None
    scope_text: str | None
    notes: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
