from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import SessionLocal, engine, Base
from models import Incident
from schemas import IncidentOut
from utils import parse_logs, detect_suspicious_events
from inference import predict_anomalies

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Network Incident Detection Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
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


@app.get("/")
def root():
    return {"message": "Backend is running"}


@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    text = content.decode("utf-8")

    events = parse_logs(text)
    incidents = detect_suspicious_events(events)
    ai_results = predict_anomalies(events)

    created = []

    for i, item in enumerate(incidents):
        ai_data = ai_results[i] if i < len(ai_results) else {}

        existing_incident = (
            db.query(Incident)
            .filter(
                Incident.source_ip == item.get("source_ip"),
                Incident.destination_ip == item.get("destination_ip"),
                Incident.timestamp == item.get("timestamp"),
                Incident.alert_type == item.get("alert_type"),
            )
            .first()
        )

        if existing_incident:
            continue

        incident = Incident(
            source_ip=item.get("source_ip"),
            destination_ip=item.get("destination_ip"),
            domain=item.get("domain"),
            timestamp=item.get("timestamp"),
            alert_type=item.get("alert_type"),
            summary=item.get("summary"),
            risk_level=item.get("risk_level"),
            recommended_action=item.get("recommended_action"),
            status=item.get("status", "Pending"),
            ai_prediction=ai_data.get("ai_prediction"),
            ai_score=ai_data.get("ai_score"),
            ai_reason=ai_data.get("ai_reason"),
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)
        created.append(incident)

    return {
        "message": "Logs processed successfully",
        "incidents_found": len(created),
    }


@app.get("/incidents", response_model=list[IncidentOut])
def get_incidents(db: Session = Depends(get_db)):
    return db.query(Incident).order_by(Incident.id.desc()).all()


@app.put("/incidents/{incident_id}/approve")
def approve_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "Approved"
    db.commit()

    return {"message": "Incident approved successfully"}


@app.put("/incidents/{incident_id}/reject")
def reject_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "Rejected"
    db.commit()

    return {"message": "Incident rejected successfully"}