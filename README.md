# AI-Driven Network Detection and Response Platform for Real-Time Intrusion Detection

A production-ready, multi-tenant NDR SaaS platform with live Suricata packet capture, hybrid ML ensemble (BiLSTM + XGBoost + Isolation Forest), MITRE ATT&CK mapping, real-time WebSocket streaming, and fully automated risk triage — no manual intervention required.

**Live at:** [roahacks.com](https://roahacks.com)

---

## What It Does

- Monitors your network interface in real time via **Suricata EVE JSON** stream
- Automatically classifies every event (DNS lookups, TLS connections, anomalies) using an ML ensemble
- Suppresses background noise (local-to-local UDP keep-alives, mDNS, ARP) — only meaningful events surface
- Medium and High risk incidents appear on the dashboard instantly via WebSocket push
- Low risk traffic is silently logged in the background
- No manual log uploads required — fully automatic

---

## Accuracy Results (Table II — Research Paper Alignment)

| Model | Accuracy | Paper Target |
|---|---|---|
| Isolation Forest | 90.6% | 91.5% |
| One-Class SVM | 64.8% | 89.7% |
| XGBoost Direct | 99.9% | ~95% |
| BiLSTM (2×128) | 22.7%* | 94.8% |
| **Ensemble (final)** | **99.8%** | **96.4%** |
| **Ensemble Macro-F1** | **99.7%** | **95.9%** |

*BiLSTM accuracy improves significantly with larger sequence datasets on GPU. The ensemble meta-learner compensates via XGBoost weighting.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python 3.11) |
| Live Capture | Suricata 8.x — EVE JSON stream on `en0` |
| ML — Sequence Model | BiLSTM (2×128 units, dropout 0.3, seq_len=20) — TensorFlow/Keras |
| ML — Anomaly Detection | Isolation Forest + One-Class SVM — scikit-learn |
| ML — Ensemble | XGBoost meta-classifier (fuses all model outputs) |
| Feature Engineering | 78-dimensional CICIDS2018 feature vectors, robust z-score normalization |
| Training Data | Synthetic CICIDS2018 + UNSW-NB15 (60,000 samples, 12 attack classes) |
| Authentication | JWT (HS256) + bcrypt |
| Database | SQLite (dev) / PostgreSQL 16 (prod) via SQLAlchemy ORM |
| Real-time | WebSocket (`uvicorn[standard]`) per-org broadcast |
| Frontend | React 18, Axios |
| Container | Docker + Docker Compose |
| Threat Framework | MITRE ATT&CK (14 tactics, 17+ techniques) |
| Log Formats | Suricata EVE JSON (live), Zeek TSV, CSV, plain text |

---

## ML Architecture

### Ensemble Stack (Section 4.2 — Research Paper)

```
Network Interface (en0)
     │
     ▼
Suricata (EVE JSON stream)
     │
     ▼
NDR Watcher (ndr_watcher.py) — noise filter + event batching
     │
     ▼
Feature Engineering (78 features — CICIDS2018 standard)
     │
     ├── Isolation Forest ──────────────────────┐
     ├── One-Class SVM ─────────────────────────┤
     ├── XGBoost (direct 12-class classifier) ──┤──▶ XGBoost Meta-Ensemble ──▶ Final Prediction
     └── BiLSTM (2×128, seq_len=20) ────────────┘        (threat score 0–1, attack category, risk tier)
```

### 12 Attack Categories (CICIDS2018)
`Benign` · `DoS-Hulk` · `PortScan` · `DDoS` · `DoS-GoldenEye` · `FTP-Patator` · `SSH-Patator` · `Bot` · `Web-BruteForce` · `Infiltration` · `Heartbleed` · `Ransomware`

### Automated Risk Tiers

| Tier | Risk Level | Threat Score | Auto Action |
|---|---|---|---|
| Tier 1 | Low | < 0.4 | Silently logged (background) |
| Tier 2 | Medium | 0.4 – 0.75 | Shown on dashboard (Monitoring) |
| Tier 3 | High | > 0.75 | Highlighted alert on dashboard (Active) |

No manual approval required — all triage is automated.

---

## Multi-Tenant SaaS Architecture

- Organization-isolated data — every query filtered by `organization_id`
- Role-based access control: `ADMIN` → `ANALYST` → `VIEWER`
- JWT access tokens with long-lived watcher service tokens
- First user per organization auto-assigned ADMIN

---

## Real-Time Operations

- WebSocket endpoint (`/ws?token=<JWT>`) — requires `uvicorn[standard]`
- Per-organization broadcast isolation
- Frontend auto-reconnects on disconnect
- Incidents appear on dashboard without page refresh
- Start/Stop watcher directly from the dashboard UI

---

## Dashboard Features

- **Live status indicator** — green (Live) / yellow (Connecting) / red (Disconnected)
- **Start / Stop watcher** — controls Suricata NDR watcher process from the UI
- **Smart noise filtering** — suppresses local↔local UDP/mDNS background traffic
- **User-friendly incident titles** — "DNS Lookup: youtube.com", "Secure Connection: api.github.com"
- **MITRE ATT&CK heatmap** — 14 tactics, color-coded by threat count
- **Incident timeline chart** — last 10 days
- **Search + filter** — by risk level / status / domain / IP
- **Download Today's Report** — exports a sorted plaintext network activity report

---

## System Architecture

```
Browser
  │
  └── React SPA (localhost:3000 dev / Nginx prod)
        │
        └── FastAPI backend (localhost:8000)
              ├── Auth         /api/v1/auth/register, /login
              ├── Incidents    /incidents  (GET, DELETE all)
              ├── Watcher      /watcher/start, /watcher/stop, /watcher/status
              ├── WebSocket    /ws?token=<JWT>
              ├── Health       /health
              └── Metrics      /metrics

Suricata (en0)
  └── eve.json → NDR Watcher → POST /upload-logs → ML ensemble → Incident stored → WS broadcast
```

---

## Running Locally

**Prerequisites:** Python 3.11+, Node 18+, Suricata 8+

```bash
git clone https://github.com/roahanb/AI-Driven-Network-Detection-and-Response-SaaS-Platform-with-Approval-Based-Response-Engine.git
cd AI-Driven-Network-Detection-and-Response-SaaS-Platform-with-Approval-Based-Response-Engine

# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install 'uvicorn[standard]' websockets
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend && npm install && npm start

# Suricata (macOS)
brew install suricata
sudo suricata -c /opt/homebrew/etc/suricata/suricata.yaml -i en0 -D
```

Open **http://localhost:3000** → register → click **▶ Start** to begin live monitoring.

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | ✗ | Register user + org |
| POST | `/api/v1/auth/login` | ✗ | Login, returns JWT |
| POST | `/upload-logs` | ✓ | Ingest Suricata events (used by watcher) |
| GET | `/incidents` | ✓ | List org incidents |
| DELETE | `/incidents` | ✓ ADMIN | Delete all incidents |
| POST | `/watcher/start` | ✓ ADMIN | Start NDR watcher subprocess |
| POST | `/watcher/stop` | ✓ ADMIN | Stop NDR watcher subprocess |
| GET | `/watcher/status` | ✓ | Watcher running state + uptime |
| GET | `/metrics` | ✓ | Platform counters |
| WS | `/ws?token=<JWT>` | ✓ | Real-time incident stream |
| GET | `/health` | ✗ | Health check |

---

## Author

**Roahan B.**
[roahacks.com](https://roahacks.com)
