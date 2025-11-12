from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import JSON, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base


class ScanStatusEnum(str, Enum):
    pending = "PENDING"
    running = "RUNNING"
    completed = "COMPLETED"
    failed = "FAILED"
    partial = "PARTIAL"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String, default=ScanStatusEnum.pending.value, nullable=False)
    region_scope = Column(JSON, nullable=False, default=list)
    caller_identity = Column(JSON, nullable=True)
    minimal_permissions = Column(JSON, nullable=True)

    regions = relationship("ScanRegion", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class ScanRegion(Base):
    __tablename__ = "scan_regions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    region = Column(String, nullable=False)
    status = Column(String, default=ScanStatusEnum.pending.value, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)

    scan = relationship("ScanRun", back_populates="regions")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    service = Column(String, nullable=False)
    rule_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False)
    evidence = Column(JSON, nullable=False)
    region = Column(String, nullable=True)
    resource_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("ScanRun", back_populates="findings")
    llm_advice = relationship("LLMAdvice", back_populates="finding", uselist=False)


class LLMAdvice(Base):
    __tablename__ = "llm_advice"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    model = Column(String, nullable=False)
    prompt_hash = Column(String, nullable=False)
    content_md = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    finding = relationship("Finding", back_populates="llm_advice")


class RuleCatalog(Base):
    __tablename__ = "rule_catalog"

    rule_id = Column(String, primary_key=True)
    service = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity_default = Column(String, nullable=False)
    cis_map = Column(JSON, nullable=True)
    docs = Column(JSON, nullable=True)
