from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, Enum as SAEnum, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.database import Base


class RiskLevel(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class IncidentStatus(str, enum.Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    ESCALATED = "Escalated"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    # Network data
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    domain = Column(String(500), nullable=True)
    timestamp = Column(String(50))
    alert_type = Column(String(255), index=True)

    # Analysis
    summary = Column(Text)
    risk_level = Column(SAEnum(RiskLevel, native_enum=False), default=RiskLevel.LOW, index=True)
    recommended_action = Column(String(500))
    status = Column(SAEnum(IncidentStatus, native_enum=False), default=IncidentStatus.PENDING, index=True)

    # ML/AI data
    ai_prediction = Column(String(50), nullable=True)
    ai_score = Column(Float, nullable=True)
    ai_reason = Column(Text, nullable=True)
    confidence_score = Column(Float, nullable=True)

    # Approval workflow
    approved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approval_comment = Column(Text, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    # Response actions
    action_taken = Column(String(500), nullable=True)
    is_false_positive = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_tactic_id = Column(String(20), nullable=True)
    mitre_technique = Column(String(200), nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)

    # Source tracking
    log_source = Column(String(255), nullable=True)
    raw_log = Column(Text, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="incidents")
    approved_by = relationship("User", foreign_keys=[approved_by_id], back_populates="approved_incidents")
    audit_logs = relationship("AuditLog", back_populates="incident", lazy="select")
