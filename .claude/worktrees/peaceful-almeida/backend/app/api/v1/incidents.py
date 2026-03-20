from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query, Request, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from datetime import datetime, timezone
from typing import Optional
import logging

from app.database import get_db
from app.models.incident import Incident, IncidentStatus, RiskLevel
from app.models.user import User
from app.models.audit import AuditLog
from app.schemas.incident import (
    IncidentOut, IncidentListResponse, ApprovalRequest,
    RejectionRequest, AnalyticsSummary,
)
from app.core.dependencies import get_current_user, require_analyst_or_above
from app.services.log_parser import parse_logs, detect_suspicious_events
from app.ml.inference import predict_anomalies
from app.ml.mitre_attack import map_to_mitre
from app.ml.feature_engineering import _domain_entropy
from app.websocket.manager import ws_manager
from app.services.notification_service import (
    send_email_alert, send_slack_alert, build_incident_email_html,
)
from app.config import settings

router = APIRouter(prefix="/incidents", tags=["Incidents"])
logger = logging.getLogger(__name__)


async def _notify_new_incident(incident: Incident, org_slug: str, analyst_emails: list[str], slack_webhook: str | None):
    """Background task: WebSocket broadcast + email + Slack notifications."""
    # WebSocket broadcast
    await ws_manager.broadcast_to_org(
        incident.organization_id,
        "new_incident",
        {
            "id": incident.id,
            "risk_level": incident.risk_level,
            "alert_type": incident.alert_type,
            "source_ip": incident.source_ip,
            "status": incident.status,
            "ai_prediction": incident.ai_prediction,
            "created_at": str(incident.created_at),
        },
    )

    # Email alerts for High/Critical
    if incident.risk_level in ("High", "Critical") and analyst_emails:
        html = build_incident_email_html(
            incident_id=incident.id,
            risk_level=str(incident.risk_level),
            alert_type=incident.alert_type or "",
            source_ip=incident.source_ip or "",
            destination_ip=incident.destination_ip or "",
            summary=incident.summary or "",
            recommended_action=incident.recommended_action or "",
        )
        await send_email_alert(
            to_emails=analyst_emails,
            subject=f"[{incident.risk_level}] Security Incident #{incident.id} - {incident.alert_type}",
            body_html=html,
        )

    # Slack alert
    if slack_webhook:
        await send_slack_alert(
            webhook_url=slack_webhook,
            incident_id=incident.id,
            risk_level=str(incident.risk_level),
            alert_type=incident.alert_type or "",
            source_ip=incident.source_ip or "",
            summary=incident.summary or "",
        )


@router.post("/upload-logs", status_code=status.HTTP_201_CREATED)
async def upload_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_above),
):
    """Upload and process network log files. Supports JSON lines, CSV, plain text."""
    if file.size and file.size > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Max {settings.MAX_UPLOAD_SIZE_MB}MB.")

    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    events = parse_logs(text)
    if not events:
        raise HTTPException(status_code=422, detail="No parseable log entries found in file.")

    incidents_data = detect_suspicious_events(events)
    ai_results = predict_anomalies(events)

    created_count = 0
    new_incidents = []

    for i, item in enumerate(incidents_data):
        ai_data = ai_results[i] if i < len(ai_results) else {}

        # Dedup check
        result = await db.execute(
            select(Incident).where(
                and_(
                    Incident.organization_id == current_user.organization_id,
                    Incident.source_ip == item.get("source_ip"),
                    Incident.destination_ip == item.get("destination_ip"),
                    Incident.timestamp == item.get("timestamp"),
                    Incident.alert_type == item.get("alert_type"),
                )
            )
        )
        if result.scalar_one_or_none():
            continue

        domain = item.get("domain") or ""
        mitre = map_to_mitre(
            alert_type=item.get("alert_type") or "",
            domain=domain,
            ai_reason=ai_data.get("ai_reason") or "",
            summary=item.get("summary") or "",
            domain_entropy=_domain_entropy(domain),
        )

        incident = Incident(
            organization_id=current_user.organization_id,
            source_ip=item.get("source_ip"),
            destination_ip=item.get("destination_ip"),
            domain=domain or None,
            timestamp=item.get("timestamp"),
            alert_type=item.get("alert_type"),
            summary=item.get("summary"),
            risk_level=item.get("risk_level", "Low"),
            recommended_action=item.get("recommended_action"),
            status=IncidentStatus.PENDING,
            ai_prediction=ai_data.get("ai_prediction"),
            ai_score=ai_data.get("ai_score"),
            ai_reason=ai_data.get("ai_reason"),
            confidence_score=ai_data.get("confidence_score"),
            mitre_tactic=mitre.get("mitre_tactic"),
            mitre_tactic_id=mitre.get("mitre_tactic_id"),
            mitre_technique=mitre.get("mitre_technique"),
            mitre_technique_id=mitre.get("mitre_technique_id"),
            log_source=file.filename,
            raw_log=item.get("raw_log"),
        )
        db.add(incident)
        await db.flush()
        created_count += 1
        new_incidents.append(incident)

    # Audit log
    db.add(AuditLog(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="upload_logs",
        details={
            "filename": file.filename,
            "total_events": len(events),
            "incidents_created": created_count,
        },
    ))

    # Get org details for notifications
    from app.models.user import Organization
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = org_result.scalar_one_or_none()

    # Get analyst emails for notifications
    analysts_result = await db.execute(
        select(User).where(
            and_(
                User.organization_id == current_user.organization_id,
                User.is_active == True,
                User.notification_email == True,
            )
        )
    )
    analyst_emails = [u.email for u in analysts_result.scalars().all()]

    # Schedule notifications
    for incident in new_incidents:
        background_tasks.add_task(
            _notify_new_incident,
            incident,
            org.slug if org else "",
            analyst_emails,
            org.slack_webhook_url if org else None,
        )

    return {
        "message": "Logs processed successfully",
        "total_events": len(events),
        "incidents_found": created_count,
        "log_source": file.filename,
    }


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    ai_prediction: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List incidents for the current organization with filtering and pagination."""
    conditions = [Incident.organization_id == current_user.organization_id]

    if status:
        conditions.append(Incident.status == status)
    if risk_level:
        conditions.append(Incident.risk_level == risk_level)
    if ai_prediction:
        conditions.append(Incident.ai_prediction == ai_prediction)
    if source_ip:
        conditions.append(Incident.source_ip.ilike(f"%{source_ip}%"))
    if alert_type:
        conditions.append(Incident.alert_type.ilike(f"%{alert_type}%"))

    count_result = await db.execute(
        select(func.count(Incident.id)).where(and_(*conditions))
    )
    total = count_result.scalar_one()

    offset = (page - 1) * page_size
    result = await db.execute(
        select(Incident)
        .where(and_(*conditions))
        .order_by(Incident.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    incidents = result.scalars().all()

    return IncidentListResponse(
        items=incidents,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Incident).where(
            and_(
                Incident.id == incident_id,
                Incident.organization_id == current_user.organization_id,
            )
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.put("/{incident_id}/approve")
async def approve_incident(
    incident_id: int,
    payload: ApprovalRequest = ApprovalRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_above),
):
    result = await db.execute(
        select(Incident).where(
            and_(
                Incident.id == incident_id,
                Incident.organization_id == current_user.organization_id,
            )
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status != IncidentStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Incident is already {incident.status}")

    incident.status = IncidentStatus.APPROVED
    incident.approved_by_id = current_user.id
    incident.approved_at = datetime.now(timezone.utc)
    incident.approval_comment = payload.comment
    incident.action_taken = payload.action_taken

    db.add(AuditLog(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        incident_id=incident_id,
        action="approve_incident",
        details={"comment": payload.comment, "action_taken": payload.action_taken},
    ))

    # Notify via WebSocket
    await ws_manager.broadcast_to_org(
        current_user.organization_id,
        "incident_updated",
        {"id": incident_id, "status": "Approved", "approved_by": current_user.full_name},
    )

    return {"message": "Incident approved", "incident_id": incident_id}


@router.put("/{incident_id}/reject")
async def reject_incident(
    incident_id: int,
    payload: RejectionRequest = RejectionRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_above),
):
    result = await db.execute(
        select(Incident).where(
            and_(
                Incident.id == incident_id,
                Incident.organization_id == current_user.organization_id,
            )
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status != IncidentStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Incident is already {incident.status}")

    incident.status = IncidentStatus.REJECTED
    incident.approved_by_id = current_user.id
    incident.approved_at = datetime.now(timezone.utc)
    incident.approval_comment = payload.comment
    incident.is_false_positive = payload.is_false_positive

    db.add(AuditLog(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        incident_id=incident_id,
        action="reject_incident",
        details={"comment": payload.comment, "is_false_positive": payload.is_false_positive},
    ))

    await ws_manager.broadcast_to_org(
        current_user.organization_id,
        "incident_updated",
        {"id": incident_id, "status": "Rejected", "rejected_by": current_user.full_name},
    )

    return {"message": "Incident rejected", "incident_id": incident_id}


@router.put("/{incident_id}/escalate")
async def escalate_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_above),
):
    result = await db.execute(
        select(Incident).where(
            and_(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = IncidentStatus.ESCALATED

    db.add(AuditLog(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        incident_id=incident_id,
        action="escalate_incident",
    ))

    await ws_manager.broadcast_to_org(
        current_user.organization_id,
        "incident_updated",
        {"id": incident_id, "status": "Escalated", "escalated_by": current_user.full_name},
    )

    return {"message": "Incident escalated", "incident_id": incident_id}


@router.get("/summary/analytics", response_model=AnalyticsSummary)
async def get_analytics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org_id = current_user.organization_id

    async def count(condition):
        r = await db.execute(select(func.count(Incident.id)).where(and_(
            Incident.organization_id == org_id, condition
        )))
        return r.scalar_one()

    total = await count(Incident.id != None)

    return AnalyticsSummary(
        total_incidents=total,
        pending=await count(Incident.status == "Pending"),
        approved=await count(Incident.status == "Approved"),
        rejected=await count(Incident.status == "Rejected"),
        resolved=await count(Incident.status == "Resolved"),
        critical=await count(Incident.risk_level == "Critical"),
        high=await count(Incident.risk_level == "High"),
        medium=await count(Incident.risk_level == "Medium"),
        low=await count(Incident.risk_level == "Low"),
        ai_detected_anomalies=await count(Incident.ai_prediction == "suspicious"),
        false_positives=await count(Incident.is_false_positive == True),
    )
