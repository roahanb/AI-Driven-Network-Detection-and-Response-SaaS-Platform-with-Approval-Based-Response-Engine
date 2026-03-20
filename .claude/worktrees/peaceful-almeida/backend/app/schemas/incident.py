from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


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
    confidence_score: Optional[float] = None
    mitre_tactic: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None


class IncidentOut(IncidentBase):
    id: int
    organization_id: int
    approved_by_id: Optional[int] = None
    approval_comment: Optional[str] = None
    approved_at: Optional[datetime] = None
    action_taken: Optional[str] = None
    is_false_positive: bool = False
    log_source: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ApprovalRequest(BaseModel):
    comment: Optional[str] = Field(None, max_length=1000)
    action_taken: Optional[str] = Field(None, max_length=500)


class RejectionRequest(BaseModel):
    comment: Optional[str] = Field(None, max_length=1000)
    is_false_positive: bool = False


class IncidentFilter(BaseModel):
    status: Optional[str] = None
    risk_level: Optional[str] = None
    ai_prediction: Optional[str] = None
    source_ip: Optional[str] = None
    alert_type: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class IncidentListResponse(BaseModel):
    items: list[IncidentOut]
    total: int
    page: int
    page_size: int
    pages: int


class AnalyticsSummary(BaseModel):
    total_incidents: int
    pending: int
    approved: int
    rejected: int
    resolved: int
    critical: int
    high: int
    medium: int
    low: int
    ai_detected_anomalies: int
    false_positives: int
    avg_response_time_hours: Optional[float] = None
