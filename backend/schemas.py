from typing import Optional
from pydantic import BaseModel


class IncidentBase(BaseModel):
    source_ip: str
    destination_ip: str
    domain: Optional[str] = None
    timestamp: str
    alert_type: str
    summary: str
    risk_level: str
    recommended_action: str
    status: str


class IncidentOut(IncidentBase):
    id: int

    class Config:
        from_attributes = True