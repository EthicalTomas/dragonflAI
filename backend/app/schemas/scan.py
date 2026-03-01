import datetime

from pydantic import BaseModel, ConfigDict


class ScanCreate(BaseModel):
    target_id: int
    scanner: str = "nuclei"
    run_id: int | None = None
    config: dict = {}


class ScanOut(BaseModel):
    id: int
    target_id: int
    run_id: int | None
    scanner: str
    status: str
    config_json: str
    progress: int | None
    log_text: str | None
    created_at: datetime.datetime
    updated_at: datetime.datetime | None

    model_config = ConfigDict(from_attributes=True)
