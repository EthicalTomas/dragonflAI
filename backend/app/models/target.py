from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func

from app.db.base import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False)
    value = Column(String, nullable=False)
    kind = Column(String, nullable=False)  # domain, ip, url, wildcard
    created_at = Column(DateTime(timezone=True), server_default=func.now())
