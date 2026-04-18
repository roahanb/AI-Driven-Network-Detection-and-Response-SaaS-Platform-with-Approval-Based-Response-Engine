"""
AI Companion — Trend Micro Vision One-style security analyst assistant.

Provides a conversational interface over incidents:
- Summarize threats
- Explain alerts in natural language
- Suggest investigation / response actions
- Answer analyst questions with incident context

Uses Anthropic Claude API when ANTHROPIC_API_KEY is set; otherwise falls back
to a deterministic rule-based responder so the feature still works in dev.
"""
from __future__ import annotations

import os
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Incident
from security import TokenData, verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai", tags=["ai-companion"])


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: List[ChatMessage] = Field(default_factory=list)
    incident_id: Optional[int] = None  # scope the question to a specific incident


class ChatResponse(BaseModel):
    reply: str
    model: str
    incident_context_used: int
    suggested_actions: List[str] = Field(default_factory=list)


class IncidentSummaryResponse(BaseModel):
    summary: str
    key_threats: List[str]
    recommended_priorities: List[str]
    model: str


# ─────────────────────────────────────────────
# Local auth / db dependencies (mirror main.py)
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
# Context gathering
# ─────────────────────────────────────────────
def _format_incident_for_context(inc: Incident) -> str:
    return (
        f"Incident #{inc.id} | {inc.risk_level or 'Unknown'} risk | "
        f"type={inc.alert_type or 'n/a'} | "
        f"src={inc.source_ip or 'n/a'} -> dst={inc.destination_ip or 'n/a'} | "
        f"domain={inc.domain or 'n/a'} | "
        f"mitre={inc.mitre_tactic or 'n/a'}/{inc.mitre_technique or 'n/a'} | "
        f"ai_score={inc.ai_score} | "
        f"status={inc.status or 'Pending'} | "
        f"summary={(inc.summary or '')[:200]}"
    )


def _gather_incident_context(
    db: Session,
    org_id: int,
    incident_id: Optional[int],
    limit: int = 25,
) -> List[Incident]:
    q = db.query(Incident).filter(Incident.organization_id == org_id)
    if incident_id is not None:
        inc = q.filter(Incident.id == incident_id).first()
        return [inc] if inc else []
    high = q.filter(Incident.risk_level == "High").order_by(Incident.id.desc()).limit(10).all()
    med = q.filter(Incident.risk_level == "Medium").order_by(Incident.id.desc()).limit(10).all()
    others = q.order_by(Incident.id.desc()).limit(10).all()
    seen, out = set(), []
    for inc in high + med + others:
        if inc.id in seen:
            continue
        seen.add(inc.id)
        out.append(inc)
        if len(out) >= limit:
            break
    return out


# ─────────────────────────────────────────────
# Claude integration + fallback
# ─────────────────────────────────────────────
SYSTEM_PROMPT = """You are the AI Companion for an NDR (Network Detection and Response) SOC platform, similar to Trend Micro Vision One Companion.

Your role:
- Help security analysts triage, investigate, and respond to network incidents
- Explain alerts in clear, actionable language
- Correlate incidents across source IPs, destinations, and MITRE ATT&CK tactics
- Suggest concrete next steps (isolate host, block IP, open ticket, hunt for related IOCs)

Style:
- Be concise and operational. Analysts are busy.
- Always ground responses in the provided incident context. Never invent data.
- When recommending actions, order them by urgency.
- If data is insufficient, say so and suggest what to gather next."""


def _call_claude(user_message: str, history: List[ChatMessage], context_blob: str) -> tuple[str, str]:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _rule_based_reply(user_message, context_blob), "rule-based-fallback"
    try:
        from anthropic import Anthropic
    except ImportError:
        logger.warning("anthropic SDK not installed; using rule-based fallback")
        return _rule_based_reply(user_message, context_blob), "rule-based-fallback"

    try:
        client = Anthropic(api_key=api_key)
        messages = []
        for m in history[-10:]:
            if m.role in ("user", "assistant") and m.content.strip():
                messages.append({"role": m.role, "content": m.content})
        messages.append({
            "role": "user",
            "content": f"## Current Incident Context\n{context_blob}\n\n## Analyst Question\n{user_message}",
        })
        model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return text or "(empty response)", model
    except Exception as e:
        logger.error(f"Claude API call failed: {e}")
        return _rule_based_reply(user_message, context_blob), "rule-based-fallback"


def _rule_based_reply(user_message: str, context_blob: str) -> str:
    q = user_message.lower()
    lines = [l for l in context_blob.strip().split("\n") if l.strip()]
    incident_count = len([l for l in lines if l.startswith("Incident #")])

    if any(k in q for k in ["summary", "overview", "summarize", "brief"]):
        high = sum(1 for l in lines if "High risk" in l)
        med = sum(1 for l in lines if "Medium risk" in l)
        return (
            f"**Current posture** — {incident_count} incidents in scope "
            f"({high} high, {med} medium).\n\n"
            f"Top priority: triage high-risk incidents first. Review repeated "
            f"source IPs (possible coordinated activity), then cluster by "
            f"MITRE tactic to see coverage gaps.\n\n"
            f"Ask me: *'what are my top 3 threats?'* or *'investigate incident #<id>'*."
        )
    if any(k in q for k in ["top", "priority", "urgent", "worst"]):
        highs = [l for l in lines if "High risk" in l][:3]
        if not highs:
            return "No high-risk incidents in current scope."
        return "**Top priorities:**\n\n" + "\n".join(f"- {l}" for l in highs)
    if any(k in q for k in ["mitre", "tactic", "technique", "att&ck"]):
        mitre_lines = [l for l in lines if "mitre=" in l and not l.split("mitre=")[1][:5].startswith("n/a")]
        if not mitre_lines:
            return "No incidents with MITRE ATT&CK mapping in current scope."
        return "**MITRE-mapped incidents:**\n\n" + "\n".join(f"- {l}" for l in mitre_lines[:10])
    if any(k in q for k in ["investigate", "detail", "explain"]):
        return (
            "**Investigation steps:**\n"
            "1. Check source/dest IP reputation (VT, AbuseIPDB)\n"
            "2. Correlate with other incidents from same source IP\n"
            "3. Check MITRE technique for known TTPs\n"
            "4. Review packet captures if available\n"
            "5. Determine blast radius across the fleet\n\n"
            "Give me a specific incident ID for targeted analysis."
        )
    if any(k in q for k in ["action", "respond", "remediate", "block"]):
        return (
            "**Response playbook:**\n"
            "1. **Contain** — Isolate affected host\n"
            "2. **Block** — Add IOC to firewall deny-list\n"
            "3. **Hunt** — Search for related IOCs fleet-wide\n"
            "4. **Forensics** — Preserve logs + memory capture\n"
            "5. **Report** — Open ticket, notify stakeholders\n\n"
            "*(Rule-based mode. Set `ANTHROPIC_API_KEY` for Claude-powered responses.)*"
        )
    return (
        f"I have {incident_count} incidents in context. I can:\n\n"
        f"- **Summarize** your current posture\n"
        f"- Show **top priority** threats\n"
        f"- Break down by **MITRE** tactic\n"
        f"- **Investigate** a specific incident\n"
        f"- Suggest **response actions**\n\n"
        f"*(Running in rule-based mode — set `ANTHROPIC_API_KEY` for full Claude-powered analysis.)*"
    )


def _extract_suggested_actions(reply: str) -> List[str]:
    actions = []
    for line in reply.split("\n"):
        s = line.strip()
        if not s:
            continue
        if s.startswith(("- ", "* ", "• ")):
            actions.append(s[2:].strip()[:120])
        elif len(s) > 3 and s[0].isdigit() and s[1] in ".)":
            actions.append(s[2:].strip()[:120])
        if len(actions) >= 5:
            break
    return actions


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@router.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    incidents = _gather_incident_context(db, user.organization_id, req.incident_id)
    context_blob = "\n".join(_format_incident_for_context(i) for i in incidents) or "(no incidents available)"
    reply, model = _call_claude(req.message, req.history, context_blob)
    return ChatResponse(
        reply=reply,
        model=model,
        incident_context_used=len(incidents),
        suggested_actions=_extract_suggested_actions(reply),
    )


@router.get("/summary", response_model=IncidentSummaryResponse)
def posture_summary(
    db: Session = Depends(_get_db),
    user: TokenData = Depends(_get_current_user),
):
    """One-shot AI summary of current security posture for the org."""
    incidents = _gather_incident_context(db, user.organization_id, None, limit=30)
    context_blob = "\n".join(_format_incident_for_context(i) for i in incidents) or "(no incidents)"

    reply, model = _call_claude(
        "Give me a 3-sentence executive summary of my current security posture, "
        "then list the top 3 key threats and top 3 recommended priorities.",
        [], context_blob,
    )

    # Heuristic split
    lines = [l.strip() for l in reply.split("\n") if l.strip()]
    summary = next((l for l in lines if not l.startswith(("-", "*", "#", "•")) and len(l) > 40), reply[:280])
    bullets = [l.lstrip("-*•#0123456789.) ").strip() for l in lines if l.startswith(("-", "*", "•"))]
    key_threats = bullets[:3] if len(bullets) >= 3 else [f"{i.alert_type or 'Event'} from {i.source_ip or 'unknown'}" for i in incidents[:3]]
    priorities = bullets[3:6] if len(bullets) >= 6 else [
        "Triage high-risk incidents",
        "Review repeated source IPs",
        "Verify MITRE coverage gaps",
    ]

    return IncidentSummaryResponse(
        summary=summary,
        key_threats=key_threats,
        recommended_priorities=priorities,
        model=model,
    )
