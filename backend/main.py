from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import SessionLocal, engine, Base
from models import Incident
from schemas import IncidentOut
from utils import parse_logs, detect_suspicious_events

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

    created = []
    for item in incidents:
        incident = Incident(**item)
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