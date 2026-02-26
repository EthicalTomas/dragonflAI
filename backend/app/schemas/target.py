from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class TargetCreate(BaseModel):
    program_id: int
    name: str
    roots: list[str]
    tags: list[str] = []

    @field_validator("roots")
    @classmethod
    def roots_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("roots must have at least one entry")
        return v


class TargetOut(BaseModel):
    id: int
    program_id: int
    name: str
    roots: list[str]
    tags: list[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
