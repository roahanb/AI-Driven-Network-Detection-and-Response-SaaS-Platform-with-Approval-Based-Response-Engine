from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="organization")
    incidents = relationship("Incident", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="ANALYST")  # ADMIN, ANALYST, VIEWER
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="users")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    domain = Column(String, nullable=True)
    timestamp = Column(String)
    alert_type = Column(String)
    summary = Column(Text)
    risk_level = Column(String)
    recommended_action = Column(String)
    status = Column(String, default="Pending")

    ai_prediction = Column(String, nullable=True)
    ai_score = Column(Float, nullable=True)
    ai_reason = Column(Text, nullable=True)

    # ML Ensemble — Paper Section 4.2 + ABRE Section 4.3
    attack_category = Column(String, nullable=True)      # e.g. "DDoS", "PortScan"
    threat_score    = Column(Float, nullable=True)       # [0.0, 1.0]
    risk_tier       = Column(Integer, nullable=True)     # 1, 2, or 3 (ABRE)

    # MITRE ATT&CK Framework
    mitre_tactic_id = Column(String, nullable=True, index=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique_id = Column(String, nullable=True, index=True)
    mitre_technique = Column(String, nullable=True)

    organization = relationship("Organization", back_populates="incidents")