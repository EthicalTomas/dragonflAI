from sqlalchemy import Column, Integer, String, Text, DateTime, func

from app.db.base import Base


class Program(Base):
    __tablename__ = "programs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    platform = Column(String, nullable=True)
    scope_raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
