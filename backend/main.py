import logging
import os
import time
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Header, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional
from datetime import datetime

from database import SessionLocal, engine, Base
from models import Incident, User, Organization
from schemas import IncidentOut
from utils import parse_logs, detect_suspicious_events
from inference import predict_anomalies
from mitre import map_to_mitre
from auth import UserRegister, UserLogin, register_user, login_user, verify_user_token
from security import TokenData, verify_token
from websocket_manager import manager as ws_manager
from logging_config import setup_logging
from metrics import metrics

# Setup structured logging
logger = setup_logging(logging.INFO)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI-Driven Network Detection and Response Platform",
    description="Production-ready incident detection and response system with ML anomaly detection and MITRE ATT&CK mapping",
    version="3.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://0.0.0.0:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> TokenData:
    """Dependency to extract and verify the current user from JWT token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    try:
        token = authorization.split(" ")[1] if " " in authorization else authorization
    except IndexError:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    return verify_user_token(token, db)


@app.get("/")
def root():
    return {"message": "Backend is running"}


@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "AI-NDR Platform",
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/metrics")
def get_metrics():
    """Get application metrics."""
    logger.info("Metrics endpoint accessed")
    return {
        "metrics": metrics.get_metrics(),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    """
    WebSocket endpoint for real-time incident notifications.
    Maintains organization-level isolation.
    Usage: ws://localhost:8000/ws?token=<JWT_TOKEN>
    """
    org_id = None
    conn_id = None

    try:
        # Authenticate and connect
        org_id, conn_id = await ws_manager.connect(websocket, token)

        # Send connection confirmation
        await ws_manager.send_to_connection(
            org_id, conn_id, "connection_established",
            {"message": f"Connected to incident stream for organization {org_id}"}
        )

        logger.info(f"WebSocket connection established for org {org_id}")

        # Keep connection alive and listen for messages
        while True:
            data = await websocket.receive_text()
            logger.debug(f"WebSocket message from org {org_id}: {data}")

            # Echo or handle commands
            if data == "ping":
                await ws_manager.send_to_connection(org_id, conn_id, "pong", {})

    except WebSocketDisconnect:
        if org_id and conn_id:
            ws_manager.disconnect(org_id, conn_id)
            logger.info(f"WebSocket disconnected for org {org_id}")

    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        if org_id and conn_id:
            ws_manager.disconnect(org_id, conn_id)


# ============= Authentication Endpoints =============

@app.post("/api/v1/auth/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user and create an organization if needed."""
    try:
        result = register_user(user_data, db)
        logger.info(f"User registered successfully: {user_data.email}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


@app.post("/api/v1/auth/login")
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login a user and return access/refresh tokens."""
    try:
        result = login_user(user_data, db)
        logger.info(f"User logged in successfully: {user_data.email}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")


# ============= Protected Endpoints =============

@app.post("/upload-logs")
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(get_current_user)
):
    """
    Upload and process network logs in JSON, CSV, or plain text format.
    Detects suspicious events and runs ML-based anomaly detection.
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(400, "File must have a name")

        logger.info(f"Processing file: {file.filename}")

        # Read and decode file
        try:
            content = await file.read()
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            logger.error(f"File {file.filename} is not UTF-8 encoded")
            raise HTTPException(400, "File must be UTF-8 encoded")
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            raise HTTPException(400, "Failed to read file")

        if not text.strip():
            raise HTTPException(400, "File is empty")

        # Parse logs
        try:
            events = parse_logs(text)
            logger.info(f"Parsed {len(events)} events from {file.filename}")
        except Exception as e:
            logger.error(f"Error parsing logs: {str(e)}")
            raise HTTPException(400, f"Failed to parse logs: {str(e)}")

        if not events:
            return {
                "message": "No valid events found in file",
                "incidents_found": 0,
            }

        # Detect suspicious events and run ML prediction
        try:
            incidents = detect_suspicious_events(events)
            ai_results = predict_anomalies(events)
            logger.info(f"Detected {len(incidents)} suspicious incidents, {len(ai_results)} AI predictions")
        except Exception as e:
            logger.error(f"Error in detection/ML: {str(e)}")
            raise HTTPException(500, f"Detection failed: {str(e)}")

        # Create incident records in database
        created = []
        skipped = 0

        try:
            for incident_item in incidents:
                # Find matching AI prediction for this incident
                # Match by finding the event with same source/dest IPs
                ai_data = {}
                source_ip = incident_item.get("source_ip")
                dest_ip = incident_item.get("destination_ip")

                for event_idx, event in enumerate(events):
                    if (event.get("source_ip") == source_ip and
                        event.get("destination_ip") == dest_ip):
                        if event_idx < len(ai_results):
                            ai_data = ai_results[event_idx]
                        break

                # Check if incident already exists
                existing_incident = (
                    db.query(Incident)
                    .filter(
                        Incident.source_ip == source_ip,
                        Incident.destination_ip == dest_ip,
                        Incident.timestamp == incident_item.get("timestamp"),
                        Incident.alert_type == incident_item.get("alert_type"),
                    )
                    .first()
                )

                if existing_incident:
                    skipped += 1
                    continue

                # Map to MITRE ATT&CK framework
                mitre_result = map_to_mitre(
                    alert_type=incident_item.get("alert_type", ""),
                    domain=incident_item.get("domain", ""),
                    ai_reason=ai_data.get("ai_reason", ""),
                    summary=incident_item.get("summary", ""),
                )

                # Create new incident
                incident = Incident(
                    organization_id=current_user.organization_id,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    domain=incident_item.get("domain"),
                    timestamp=incident_item.get("timestamp"),
                    alert_type=incident_item.get("alert_type"),
                    summary=incident_item.get("summary"),
                    risk_level=incident_item.get("risk_level"),
                    recommended_action=incident_item.get("recommended_action"),
                    status=incident_item.get("status", "Pending"),
                    ai_prediction=ai_data.get("ai_prediction"),
                    ai_score=ai_data.get("ai_score"),
                    ai_reason=ai_data.get("ai_reason"),
                )

                # Add MITRE ATT&CK mapping if found
                if mitre_result:
                    tactic_id, tactic_name, technique_id, technique_name = mitre_result
                    incident.mitre_tactic_id = tactic_id
                    incident.mitre_tactic = tactic_name
                    incident.mitre_technique_id = technique_id
                    incident.mitre_technique = technique_name
                    logger.debug(f"Mapped incident to MITRE {tactic_id}/{technique_id}")

                db.add(incident)

            # Commit all changes at once
            db.commit()

            # Refresh created incidents and broadcast via WebSocket
            for incident in db.query(Incident).filter(
                Incident.status == "Pending"
            ).order_by(Incident.id.desc()).limit(len(incidents)).all():
                created.append(incident)

                # Broadcast incident creation to organization members
                import asyncio
                asyncio.create_task(
                    ws_manager.broadcast_to_org(
                        current_user.organization_id,
                        "incident_created",
                        {
                            "incident_id": incident.id,
                            "source_ip": incident.source_ip,
                            "destination_ip": incident.destination_ip,
                            "alert_type": incident.alert_type,
                            "risk_level": incident.risk_level,
                            "timestamp": incident.timestamp.isoformat() if incident.timestamp else None,
                            "mitre_tactic": incident.mitre_tactic,
                            "mitre_technique": incident.mitre_technique,
                        }
                    )
                )

            logger.info(f"Created {len(created)} incidents, skipped {skipped} duplicates")

            # Track metrics
            metrics.increment_counter("logs_uploaded")
            metrics.increment_counter("incidents_created", len(created))
            metrics.increment_counter("incidents_skipped", skipped)

        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Database error: {str(e)}")
            metrics.increment_counter("upload_errors")
            raise HTTPException(500, "Database error while saving incidents")
        except Exception as e:
            db.rollback()
            logger.error(f"Unexpected error creating incidents: {str(e)}")
            metrics.increment_counter("upload_errors")
            raise HTTPException(500, f"Error saving incidents: {str(e)}")

        return {
            "message": "Logs processed successfully",
            "incidents_found": len(created),
            "duplicates_skipped": skipped,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in upload_logs: {str(e)}")
        raise HTTPException(500, "Internal server error")


@app.get("/incidents", response_model=list[IncidentOut])
def get_incidents(
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(get_current_user)
):
    """Get incidents for the current user's organization."""
    return db.query(Incident).filter(
        Incident.organization_id == current_user.organization_id
    ).order_by(Incident.id.desc()).all()


@app.put("/incidents/{incident_id}/approve")
async def approve_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(get_current_user)
):
    """Approve an incident (requires ANALYST or ADMIN role)."""
    if current_user.role == "VIEWER":
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    incident = db.query(Incident).filter(
        Incident.id == incident_id,
        Incident.organization_id == current_user.organization_id
    ).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "Approved"
    db.commit()

    # Broadcast status change
    import asyncio
    asyncio.create_task(
        ws_manager.broadcast_to_org(
            current_user.organization_id,
            "incident_approved",
            {
                "incident_id": incident_id,
                "status": "Approved",
                "approved_by": current_user.email,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    )

    metrics.increment_counter("incidents_approved")
    logger.info(f"Incident {incident_id} approved by {current_user.email}")

    return {"message": "Incident approved successfully"}


@app.put("/incidents/{incident_id}/reject")
async def reject_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(get_current_user)
):
    """Reject an incident (requires ANALYST or ADMIN role)."""
    if current_user.role == "VIEWER":
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    incident = db.query(Incident).filter(
        Incident.id == incident_id,
        Incident.organization_id == current_user.organization_id
    ).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "Rejected"
    db.commit()

    # Broadcast status change
    import asyncio
    asyncio.create_task(
        ws_manager.broadcast_to_org(
            current_user.organization_id,
            "incident_rejected",
            {
                "incident_id": incident_id,
                "status": "Rejected",
                "rejected_by": current_user.email,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    )

    metrics.increment_counter("incidents_rejected")
    logger.info(f"Incident {incident_id} rejected by {current_user.email}")

    return {"message": "Incident rejected successfully"}