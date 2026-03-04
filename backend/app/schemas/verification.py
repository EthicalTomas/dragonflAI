import datetime

from pydantic import BaseModel, field_validator

_VALID_METHODS = {"http_replay", "dns_recheck", "screenshot"}
_VALID_STATUSES = {"queued", "running", "confirmed", "unconfirmed", "inconclusive", "failed"}


class VerificationCreate(BaseModel):
    target_id: int
    run_id: int | None = None
    finding_id: int | None = None
    method: str = "http_replay"

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        if v not in _VALID_METHODS:
            raise ValueError(
                f"method must be one of: {', '.join(sorted(_VALID_METHODS))}"
            )
        return v


class VerificationOut(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    target_id: int
    run_id: int | None
    finding_id: int | None
    status: str
    method: str
    evidence_json: str | None
    log_text: str | None
    created_at: datetime.datetime
    updated_at: datetime.datetime | None
