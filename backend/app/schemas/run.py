import datetime

from pydantic import BaseModel, ConfigDict


class RunCreate(BaseModel):
    target_id: int
    modules: list[str] = ["dummy"]
    config: dict = {}


class RunOut(BaseModel):
    id: int
    target_id: int
    status: str
    progress: int
    log_text: str
    created_at: datetime.datetime
    started_at: datetime.datetime | None
    finished_at: datetime.datetime | None

    model_config = ConfigDict(from_attributes=True)
