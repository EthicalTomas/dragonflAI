import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class VerificationStatus:
    QUEUED = "queued"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class Verification(Base):
    __tablename__ = "verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), index=True, nullable=False)
    run_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("runs.id"), index=True, nullable=True)
    finding_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("findings.id"), index=True, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default=VerificationStatus.QUEUED, index=True, nullable=False
    )
    method: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.utcnow(), nullable=False
    )
    updated_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
