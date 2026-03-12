import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus:
    DRAFT = "draft"
    NEEDS_REVIEW = "needs_review"
    READY_TO_SUBMIT = "ready_to_submit"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"

    # Legacy alias kept for backwards compatibility
    READY = "ready_to_submit"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("runs.id"), index=True, nullable=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, default=Severity.MEDIUM, index=True)
    status: Mapped[str] = mapped_column(String, default=FindingStatus.DRAFT, index=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameter: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    steps_to_reproduce: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_paths_json: Mapped[str] = mapped_column(Text, default="[]")
    request_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String, nullable=True)
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Human-review fields — must be set via the /review endpoint before export/submit
    reviewed_by_human: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String, nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
