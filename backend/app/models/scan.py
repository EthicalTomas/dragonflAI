import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class ScanStatus:
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), index=True, nullable=False)
    run_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("runs.id"), index=True, nullable=True)
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.QUEUED, index=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    progress: Mapped[int | None] = mapped_column(Integer, nullable=True)
    log_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.utcnow(), nullable=False
    )
    updated_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), index=True, nullable=False)
    run_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("runs.id"), index=True, nullable=True)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    template_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    matched_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    raw_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.utcnow(), nullable=False
    )
