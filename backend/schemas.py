from typing import Optional
from pydantic import BaseModel


class IncidentBase(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    timestamp: Optional[str] = None
    alert_type: Optional[str] = None
    summary: Optional[str] = None
    risk_level: Optional[str] = None
    recommended_action: Optional[str] = None
    status: Optional[str] = None
    ai_prediction: Optional[str] = None
    ai_score: Optional[float] = None
    ai_reason: Optional[str] = None
    # ML Ensemble fields (paper Section 4.2 + ABRE 4.3)
    attack_category: Optional[str] = None
    threat_score: Optional[float] = None
    risk_tier: Optional[int] = None
    # MITRE ATT&CK
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None


class IncidentOut(IncidentBase):
    id: int

    class Config:
        from_attributes = True