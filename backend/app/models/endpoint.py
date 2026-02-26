import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class EndpointSource:
    HTTPX = "httpx"
    KATANA = "katana"
    GAU = "gau"
    WAYBACK = "waybackurls"
    BURP = "burp"
    ZAP = "zap"
    MANUAL = "manual"


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("target_id", "url", "method", name="uq_endpoint_target_url_method"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), index=True, nullable=False)
    asset_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("assets.id"), index=True, nullable=True)
    run_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("runs.id"), index=True, nullable=True)
    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    scheme: Mapped[str | None] = mapped_column(String, nullable=True)
    host: Mapped[str] = mapped_column(String, nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    method: Mapped[str] = mapped_column(String, default="GET")
    params_json: Mapped[str] = mapped_column(Text, default="[]")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String, nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String, nullable=False, index=True)
    is_interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    interesting_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_headers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_headers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    is_new: Mapped[bool] = mapped_column(Boolean, default=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
