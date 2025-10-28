from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, func, Table, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import BaseNVD as Base


class CPEData(Base):
    __tablename__ = "cpe_data"
    id = Column(Integer, primary_key=True)
    cpe_name = Column(Text, unique=True, nullable=False)
    cpe_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class CVEData(Base):
    __tablename__ = "cve_data"
    id = Column(Integer, primary_key=True)
    cve_id = Column(Text, unique=True, nullable=False)
    cve_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class CWEData(Base):
    __tablename__ = "cwe_data"
    id = Column(Integer, primary_key=True)
    cwe_id = Column(Text, unique=True, nullable=False)
    cwe_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


