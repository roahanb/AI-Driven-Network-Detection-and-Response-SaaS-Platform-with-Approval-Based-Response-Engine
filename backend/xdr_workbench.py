"""
XDR Workbench — Trend Micro Vision One-style unified triage.

Endpoints:
- GET /api/v1/xdr/workbench         - Workbench overview (top assets, correlation clusters)
- GET /api/v1/xdr/incidents/{id}    - Unified incident detail (timeline + correlations + evidence)
- GET /api/v1/xdr/assets            - Asset-centric view (group incidents by IP)
- GET /api/v1/xdr/timeline          - Time-ordered event stream across all incidents
- GET /api/v1/xdr/correlate/{id}    - Correlated incidents for a given incident
"""
from __future__ import annotations

import logging
from collections import defaultdict, Counter
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Incident
from security import TokenData, verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/xdr", tags=["xdr-workbench"])


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────
class AssetSummary(BaseModel):
    ip: str
    role: str  # "source" | "destination" | "both"
    incident_count: int
    high_risk_count: int
    medium_risk_count: int
    last_seen: Optional[str]
    mitre_tactics: List[str]
    risk_score: float  # 0-100


class CorrelationCluster(BaseModel):
    cluster_id: str
    pattern: str         # "same_source_ip" | "same_mitre_tactic" | "same_destination"
    pivot_value: str     # the shared attribute
    incident_ids: List[int]
    incident_count: int
    highest_risk: str
    mitre_tactics: List[str]


class TimelineEvent(BaseModel):
    incident_id: int
    timestamp: Optional[str]
    alert_type: str
    risk_level: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    mitre_tactic: Optional[str]
    summary: str


class WorkbenchOverview(BaseModel):
    total_incidents: int
    open_incidents: int
    high_risk_count: int
    unique_source_ips: int
    unique_destinations: int
    top_assets: List[AssetSummary]
    correlation_clusters: List[CorrelationCluster]
    mitre_coverage: Dict[str, int]
    risk_trend_7d: List[Dict[str, Any]]


class IncidentDetail(BaseModel):
    incident: Dict[str, Any]
    related_incidents: List[Dict[str, Any]]
    timeline: List[TimelineEvent]
    asset_context: List[AssetSummary]
    evidence: Dict[str, Any]
    investigation_checklist: List[Dict[str, Any]]


# ─────────────────────────────────────────────
# Auth / DB
# ─────────────────────────────────────────────
def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _get_current_user(authorization: Optional[str] = Header(None)) -> TokenData:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    token = authorization.split(" ", 1)[1]
    data = verify_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return data


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def _incident_to_dict(inc: Incident) -> Dict[str, Any]:
    return {
        "id": inc.id,
        "organization_id": inc.organization_id,
        "source_ip": inc.source_ip,
        "destination_ip": inc.destination_ip,
        "domain": inc.domain,
        "timestamp": inc.timestamp,
        "alert_type": inc.alert_type,
        "summary": inc.summary,
        "risk_level": inc.risk_level,
        "recommended_action": inc.recommended_action,
        "status": inc.status,
        "ai_prediction": inc.ai_prediction,
        "ai_score": inc.ai_score,
        "ai_reason": inc.ai_reason,
        "attack_category": inc.attack_category,
        "threat_score": inc.threat_score,
        "risk_tier": inc.risk_tier,
        "mitre_tactic_id": inc.mitre_tactic_id,
        "mitre_tactic": inc.mitre_tactic,
        "mitre_technique_id": inc.mitre_technique_id,
        "mitre_technique": inc.mitre_technique,
    }


def _parse_ts(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str[:26], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts_str.replace("Z", ""))
    except Exception:
        return None


def _risk_weight(risk: Optional[str]) -> float:
    return {"High": 40.0, "Medium": 15.0, "Low": 5.0}.get(risk or "", 2.0)


def _build_asset_summaries(incidents: List[Incident], top_n: int = 10) -> List[AssetSummary]:
    """Aggregate incidents per IP and score."""
    asset_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "ip": "", "as_src": 0, "as_dst": 0,
        "count": 0, "high": 0, "med": 0,
        "last_seen": None, "mitre": set(),
    })

    for inc in incidents:
        for ip, is_src in [(inc.source_ip, True), (inc.destination_ip, False)]:
            if not ip:
                continue
            d = asset_data[ip]
            d["ip"] = ip
            if is_src:
                d["as_src"] += 1
            else:
                d["as_dst"] += 1
            d["count"] += 1
            if inc.risk_level == "High":
                d["high"] += 1
            elif inc.risk_level == "Medium":
                d["med"] += 1
            if inc.timestamp and (d["last_seen"] is None or inc.timestamp > d["last_seen"]):
                d["last_seen"] = inc.timestamp
            if inc.mitre_tactic:
                d["mitre"].add(inc.mitre_tactic)

    summaries: List[AssetSummary] = []
    for ip, d in asset_data.items():
        role = "both" if d["as_src"] and d["as_dst"] else ("source" if d["as_src"] else "destination")
        risk_score = min(100.0, d["high"] * 25 + d["med"] * 10 + d["count"] * 2)
        summaries.append(AssetSummary(
            ip=ip,
            role=role,
            incident_count=d["count"],
            high_risk_count=d["high"],
            medium_risk_count=d["med"],
            last_seen=d["last_seen"],
            mitre_tactics=sorted(d["mitre"]),
            risk_score=round(risk_score, 1),
        ))
    summaries.sort(key=lambda a: a.risk_score, reverse=True)
    return summaries[:top_n]


def _build_correlation_clusters(incidents: List[Incident], min_cluster_size: int = 2) -> List[CorrelationCluster]:
    """Group incidents that share attributes — Trend-style correlation."""
    clusters: List[CorrelationCluster] = []

    # 1. Same source IP
    by_src: Dict[str, List[Incident]] = defaultdict(list)
    for inc in incidents:
        if inc.source_ip:
            by_src[inc.source_ip].append(inc)
    for ip, group in by_src.items():
        if len(group) >= min_cluster_size:
            clusters.append(CorrelationCluster(
                cluster_id=f"src-{ip}",
                pattern="same_source_ip",
                pivot_value=ip,
                incident_ids=[i.id for i in group],
                incident_count=len(group),
                highest_risk=_highest_risk([i.risk_level for i in group]),
                mitre_tactics=sorted({i.mitre_tactic for i in group if i.mitre_tactic}),
            ))

    # 2. Same MITRE tactic (cross-source campaigns)
    by_tactic: Dict[str, List[Incident]] = defaultdict(list)
    for inc in incidents:
        if inc.mitre_tactic:
            by_tactic[inc.mitre_tactic].append(inc)
    for tactic, group in by_tactic.items():
        unique_srcs = {i.source_ip for i in group if i.source_ip}
        if len(group) >= min_cluster_size and len(unique_srcs) >= 2:
            clusters.append(CorrelationCluster(
                cluster_id=f"mitre-{tactic}",
                pattern="same_mitre_tactic",
                pivot_value=tactic,
                incident_ids=[i.id for i in group],
                incident_count=len(group),
                highest_risk=_highest_risk([i.risk_level for i in group]),
                mitre_tactics=[tactic],
            ))

    # 3. Same destination
    by_dst: Dict[str, List[Incident]] = defaultdict(list)
    for inc in incidents:
        if inc.destination_ip:
            by_dst[inc.destination_ip].append(inc)
    for ip, group in by_dst.items():
        unique_srcs = {i.source_ip for i in group if i.source_ip}
        if len(group) >= min_cluster_size and len(unique_srcs) >= 2:
            clusters.append(CorrelationCluster(
                cluster_id=f"dst-{ip}",
                pattern="same_destination",
                pivot_value=ip,
                incident_ids=[i.id for i in group],
                incident_count=len(group),
                highest_risk=_highest_risk([i.risk_level for i in group]),
                mitre_tactics=sorted({i.mitre_tactic for i in group if i.mitre_tactic}),
            ))

    # Order by severity then cluster size
    risk_order = {"High": 3, "Medium": 2, "Low": 1, "": 0}
    clusters.sort(key=lambda c: (risk_order.get(c.highest_risk, 0), c.incident_count), reverse=True)
    return clusters[:12]


def _highest_risk(risks: List[str]) -> str:
    for r in ("High", "Medium", "Low"):
        if r in risks:
            return r
    return risks[0] if risks else ""


def _build_timeline(incidents: List[Incident], limit: int = 50) -> List[TimelineEvent]:
    events = [TimelineEvent(
        incident_id=i.id,
        timestamp=i.timestamp,
        alert_type=i.alert_type or "Unknown",
        risk_level=i.risk_level or "Low",
        source_ip=i.source_ip,
        destination_ip=i.destination_ip,
        mitre_tactic=i.mitre_tactic,
        summary=(i.summary or "")[:200],
    ) for i in incidents]

    events.sort(
        key=lambda e: (_parse_ts(e.timestamp) or datetime.min, e.incident_id),
        reverse=True,
    )
    return events[:limit]


def _risk_trend_7d(incidents: List[Incident]) -> List[Dict[str, Any]]:
    buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: {"high": 0, "medium": 0, "low": 0})
    for inc in incidents:
        ts = _parse_ts(inc.timestamp)
        if not ts:
            continue
        day = ts.strftime("%Y-%m-%d")
        risk = (inc.risk_level or "").lower()
        if risk in buckets[day]:
            buckets[day][risk] += 1
    out = [{"date": k, **v} for k, v in buckets.items()]
    out.sort(key=lambda x: x["date"])
    return out[-7:]


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@router.get("/workbench", response_model=WorkbenchOverview)
def workbench_overview(
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    incidents = db.query(Incident).filter(
        Incident.organization_id == user.organization_id
    ).order_by(Incident.id.desc()).limit(500).all()

    open_ = [i for i in incidents if (i.status or "Pending") not in ("Approved", "Rejected", "Cleared")]
    high_risk = [i for i in incidents if i.risk_level == "High"]
    src_ips = {i.source_ip for i in incidents if i.source_ip}
    dst_ips = {i.destination_ip for i in incidents if i.destination_ip}

    mitre_coverage = Counter(i.mitre_tactic for i in incidents if i.mitre_tactic)

    return WorkbenchOverview(
        total_incidents=len(incidents),
        open_incidents=len(open_),
        high_risk_count=len(high_risk),
        unique_source_ips=len(src_ips),
        unique_destinations=len(dst_ips),
        top_assets=_build_asset_summaries(incidents, top_n=8),
        correlation_clusters=_build_correlation_clusters(incidents),
        mitre_coverage=dict(mitre_coverage),
        risk_trend_7d=_risk_trend_7d(incidents),
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def incident_detail(
    incident_id: int,
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    inc = db.query(Incident).filter(
        Incident.id == incident_id,
        Incident.organization_id == user.organization_id,
    ).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Find related incidents — shared IP or MITRE tactic
    filters = []
    if inc.source_ip:
        filters.append(Incident.source_ip == inc.source_ip)
        filters.append(Incident.destination_ip == inc.source_ip)
    if inc.destination_ip:
        filters.append(Incident.destination_ip == inc.destination_ip)
        filters.append(Incident.source_ip == inc.destination_ip)
    if inc.mitre_tactic:
        filters.append(Incident.mitre_tactic == inc.mitre_tactic)

    related: List[Incident] = []
    if filters:
        from sqlalchemy import or_
        related = db.query(Incident).filter(
            Incident.organization_id == user.organization_id,
            Incident.id != inc.id,
            or_(*filters),
        ).order_by(Incident.id.desc()).limit(25).all()

    asset_context = _build_asset_summaries([inc] + related, top_n=5)

    # Investigation checklist — action items the analyst should complete
    checklist = [
        {"id": "verify-source", "label": f"Verify source IP reputation: {inc.source_ip or 'N/A'}", "done": False},
        {"id": "verify-dest", "label": f"Verify destination: {inc.destination_ip or 'N/A'}", "done": False},
        {"id": "correlate", "label": f"Review {len(related)} correlated incidents", "done": False},
        {"id": "mitre", "label": f"Check MITRE {inc.mitre_tactic or 'tactic'} coverage", "done": False},
        {"id": "blast-radius", "label": "Determine blast radius across the fleet", "done": False},
        {"id": "contain", "label": "Containment decision: isolate host?", "done": False},
        {"id": "ticket", "label": "Open SOAR / ticketing workflow", "done": False},
    ]

    evidence = {
        "ai_prediction": inc.ai_prediction,
        "ai_score": inc.ai_score,
        "ai_reason": inc.ai_reason,
        "threat_score": inc.threat_score,
        "risk_tier": inc.risk_tier,
        "attack_category": inc.attack_category,
        "mitre_tactic_id": inc.mitre_tactic_id,
        "mitre_technique_id": inc.mitre_technique_id,
        "raw_summary": inc.summary,
        "related_count": len(related),
    }

    return IncidentDetail(
        incident=_incident_to_dict(inc),
        related_incidents=[_incident_to_dict(r) for r in related],
        timeline=_build_timeline([inc] + related, limit=25),
        asset_context=asset_context,
        evidence=evidence,
        investigation_checklist=checklist,
    )


@router.get("/assets", response_model=List[AssetSummary])
def assets_view(
    limit: int = 20,
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    incidents = db.query(Incident).filter(
        Incident.organization_id == user.organization_id
    ).limit(1000).all()
    return _build_asset_summaries(incidents, top_n=limit)


@router.get("/timeline", response_model=List[TimelineEvent])
def timeline(
    limit: int = 100,
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    incidents = db.query(Incident).filter(
        Incident.organization_id == user.organization_id
    ).order_by(Incident.id.desc()).limit(limit).all()
    return _build_timeline(incidents, limit=limit)


@router.get("/correlate/{incident_id}")
def correlate(
    incident_id: int,
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    inc = db.query(Incident).filter(
        Incident.id == incident_id,
        Incident.organization_id == user.organization_id,
    ).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    reasons = []
    from sqlalchemy import or_, and_
    filters = []
    if inc.source_ip:
        filters.append(("shared source IP", Incident.source_ip == inc.source_ip))
    if inc.destination_ip:
        filters.append(("shared destination IP", Incident.destination_ip == inc.destination_ip))
    if inc.mitre_tactic:
        filters.append(("shared MITRE tactic", Incident.mitre_tactic == inc.mitre_tactic))
    if inc.alert_type:
        filters.append(("shared alert type", Incident.alert_type == inc.alert_type))

    correlations = []
    for reason, cond in filters:
        related = db.query(Incident).filter(
            Incident.organization_id == user.organization_id,
            Incident.id != inc.id,
            cond,
        ).order_by(Incident.id.desc()).limit(20).all()
        if related:
            correlations.append({
                "reason": reason,
                "incident_ids": [r.id for r in related],
                "count": len(related),
            })

    return {"incident_id": inc.id, "correlations": correlations}
