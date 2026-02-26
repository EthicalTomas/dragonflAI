from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

_ALLOWED_ASSET_TYPES = {"subdomain", "ip", "cidr"}


class AssetCreate(BaseModel):
    target_id: int
    run_id: int | None = None
    asset_type: str
    value: str
    resolved_ips: list[str] = []
    tags: list[str] = []
    notes: str | None = None

    @field_validator("asset_type")
    @classmethod
    def asset_type_allowed(cls, v: str) -> str:
        if v not in _ALLOWED_ASSET_TYPES:
            allowed = ", ".join(sorted(_ALLOWED_ASSET_TYPES))
            raise ValueError(f"asset_type must be one of: {allowed}")
        return v

    @field_validator("value")
    @classmethod
    def value_lowercase(cls, v: str) -> str:
        if len(v) < 1:
            raise ValueError("value must have at least 1 character")
        return v.lower()


class AssetUpdate(BaseModel):
    is_alive: bool | None = None
    status_code: int | None = None
    title: str | None = None
    tech: list[str] = []
    web_server: str | None = None
    content_length: int | None = None
    cdn: str | None = None
    ports: list[dict] = []
    tags: list[str] = []
    notes: str | None = None


class AssetOut(BaseModel):
    id: int
    target_id: int
    run_id: int | None
    asset_type: str
    value: str
    resolved_ips: list[str]
    is_alive: bool | None
    status_code: int | None
    title: str | None
    tech: list[str]
    web_server: str | None
    content_length: int | None
    cdn: str | None
    ports: list[dict]
    first_seen_at: datetime
    last_seen_at: datetime
    is_new: bool
    tags: list[str]
    notes: str | None

    model_config = ConfigDict(from_attributes=True)


class AssetSummary(BaseModel):
    id: int
    asset_type: str
    value: str
    is_alive: bool | None
    status_code: int | None
    title: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    is_new: bool

    model_config = ConfigDict(from_attributes=True)
