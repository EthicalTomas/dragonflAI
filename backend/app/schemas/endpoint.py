import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.models.endpoint import EndpointSource

_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_ALLOWED_SOURCES = {
    EndpointSource.HTTPX,
    EndpointSource.KATANA,
    EndpointSource.GAU,
    EndpointSource.WAYBACK,
    EndpointSource.BURP,
    EndpointSource.ZAP,
    EndpointSource.MANUAL,
}


class EndpointCreate(BaseModel):
    target_id: int
    asset_id: int | None = None
    run_id: int | None = None
    url: str = Field(min_length=1)
    method: str = "GET"
    source: str
    params: list[dict] = []
    status_code: int | None = None
    content_type: str | None = None
    tags: list[str] = []
    notes: str | None = None

    @field_validator("method")
    @classmethod
    def method_allowed(cls, v: str) -> str:
        v = v.upper()
        if v not in _ALLOWED_METHODS:
            allowed = ", ".join(sorted(_ALLOWED_METHODS))
            raise ValueError(f"method must be one of: {allowed}")
        return v

    @field_validator("source")
    @classmethod
    def source_allowed(cls, v: str) -> str:
        if v not in _ALLOWED_SOURCES:
            allowed = ", ".join(sorted(_ALLOWED_SOURCES))
            raise ValueError(f"source must be one of: {allowed}")
        return v


class EndpointOut(BaseModel):
    id: int
    target_id: int
    asset_id: int | None
    run_id: int | None
    url: str
    scheme: str | None
    host: str
    port: int | None
    path: str | None
    method: str
    params: list[dict]
    status_code: int | None
    content_type: str | None
    content_length: int | None
    source: str
    is_interesting: bool
    interesting_reason: str | None
    request_headers: dict | None
    response_headers: dict | None
    first_seen_at: datetime.datetime
    last_seen_at: datetime.datetime
    is_new: bool
    tags: list[str]
    notes: str | None

    model_config = ConfigDict(from_attributes=True)


class EndpointSummary(BaseModel):
    id: int
    url: str
    method: str
    status_code: int | None
    source: str
    is_interesting: bool
    interesting_reason: str | None
    first_seen_at: datetime.datetime
    is_new: bool

    model_config = ConfigDict(from_attributes=True)


class EndpointFilter(BaseModel):
    target_id: int | None = None
    asset_id: int | None = None
    source: str | None = None
    method: str | None = None
    is_interesting: bool | None = None
    status_code_min: int | None = None
    status_code_max: int | None = None
    path_contains: str | None = None
    param_name_contains: str | None = None
