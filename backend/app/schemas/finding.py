from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


class FindingCreate(BaseModel):
    target_id: int
    run_id: int | None = None
    title: str
    vulnerability_type: str
    severity: str = "medium"
    url: str | None = None
    parameter: str | None = None
    description: str
    steps_to_reproduce: str
    impact: str
    remediation: str | None = None
    evidence_paths: list[str] = []
    request_response: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[str] = []
    notes: str | None = None

    @field_validator("title")
    @classmethod
    def title_length(cls, v: str) -> str:
        if len(v) < 5:
            raise ValueError("title must be at least 5 characters")
        if len(v) > 200:
            raise ValueError("title must be at most 200 characters")
        return v

    @field_validator("description", "steps_to_reproduce")
    @classmethod
    def validate_detailed_text_length(cls, v: str, info: object) -> str:
        field_name = getattr(info, "field_name", "field")
        if len(v) < 20:
            raise ValueError(f"{field_name} must be at least 20 characters")
        return v

    @field_validator("impact")
    @classmethod
    def impact_min_length(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("impact must be at least 10 characters")
        return v

    @field_validator("severity")
    @classmethod
    def severity_allowed(cls, v: str) -> str:
        if v not in _ALLOWED_SEVERITIES:
            allowed = ", ".join(sorted(_ALLOWED_SEVERITIES))
            raise ValueError(f"severity must be one of: {allowed}")
        return v

    @field_validator("cvss_score")
    @classmethod
    def cvss_score_range(cls, v: float | None) -> float | None:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("cvss_score must be between 0.0 and 10.0 inclusive")
        return v


class FindingUpdate(BaseModel):
    target_id: int | None = None
    run_id: int | None = None
    title: str | None = None
    vulnerability_type: str | None = None
    severity: str | None = None
    url: str | None = None
    parameter: str | None = None
    description: str | None = None
    steps_to_reproduce: str | None = None
    impact: str | None = None
    remediation: str | None = None
    evidence_paths: list[str] | None = None
    request_response: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[str] | None = None
    notes: str | None = None

    @field_validator("title")
    @classmethod
    def title_length(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v) < 5:
            raise ValueError("title must be at least 5 characters")
        if len(v) > 200:
            raise ValueError("title must be at most 200 characters")
        return v

    @field_validator("description", "steps_to_reproduce")
    @classmethod
    def validate_detailed_text_length(cls, v: str | None, info: object) -> str | None:
        if v is None:
            return v
        field_name = getattr(info, "field_name", "field")
        if len(v) < 20:
            raise ValueError(f"{field_name} must be at least 20 characters")
        return v

    @field_validator("impact")
    @classmethod
    def impact_min_length(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v) < 10:
            raise ValueError("impact must be at least 10 characters")
        return v

    @field_validator("severity")
    @classmethod
    def severity_allowed(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in _ALLOWED_SEVERITIES:
            allowed = ", ".join(sorted(_ALLOWED_SEVERITIES))
            raise ValueError(f"severity must be one of: {allowed}")
        return v

    @field_validator("cvss_score")
    @classmethod
    def cvss_score_range(cls, v: float | None) -> float | None:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("cvss_score must be between 0.0 and 10.0 inclusive")
        return v


class FindingOut(BaseModel):
    id: int
    target_id: int
    run_id: int | None
    title: str
    vulnerability_type: str
    severity: str
    status: str
    url: str | None
    parameter: str | None
    description: str
    steps_to_reproduce: str
    impact: str
    remediation: str | None
    evidence_paths: list[str]
    request_response: str | None
    cvss_score: float | None
    cvss_vector: str | None
    references: list[str]
    notes: str | None
    report_markdown: str | None
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class FindingSummary(BaseModel):
    id: int
    title: str
    vulnerability_type: str
    severity: str
    status: str
    url: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
