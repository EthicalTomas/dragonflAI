from datetime import datetime

from pydantic import BaseModel

from app.models.run import RunStatus


class RunCreate(BaseModel):
    program_id: int


class RunOut(RunCreate):
    id: int
    status: RunStatus
    job_id: str | None = None
    created_at: datetime
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}
