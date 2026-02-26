import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class AssetType:
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("target_id", "asset_type", "value", name="uq_asset_target_type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), index=True, nullable=False)
    run_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("runs.id"), index=True, nullable=True)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    resolved_ips_json: Mapped[str] = mapped_column(Text, default="[]")
    is_alive: Mapped[bool | None] = mapped_column(Boolean, default=None, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tech_json: Mapped[str] = mapped_column(Text, default="[]")
    web_server: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cdn: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ports_json: Mapped[str] = mapped_column(Text, default="[]")
    first_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.utcnow(), nullable=False
    )
    last_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.utcnow(), nullable=False
    )
    is_new: Mapped[bool] = mapped_column(Boolean, default=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
