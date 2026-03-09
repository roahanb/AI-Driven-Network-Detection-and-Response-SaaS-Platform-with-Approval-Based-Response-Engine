from sqlalchemy import Column, Integer, String, Text
from database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    domain = Column(String, nullable=True)
    timestamp = Column(String)
    alert_type = Column(String)
    summary = Column(Text)
    risk_level = Column(String)
    recommended_action = Column(String)
    status = Column(String, default="Pending")