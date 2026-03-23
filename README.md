# AI-NDR — AI-Driven Network Detection and Response Platform

A production-ready, multi-tenant Network Detection and Response (NDR) SaaS platform built on a hybrid ML ensemble stack (BiLSTM + XGBoost + Isolation Forest + One-Class SVM), MITRE ATT&CK mapping, real-time WebSocket streaming, and a 3-tier human-in-the-loop approval workflow (ABRE).

**Live at:** [roahacks.com](https://roahacks.com)

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
| ML — Sequence Model | BiLSTM (2×128 units, dropout 0.3, seq_len=20) — TensorFlow/Keras |
| ML — Anomaly Detection | Isolation Forest + One-Class SVM — scikit-learn |
| ML — Ensemble | XGBoost meta-classifier (fuses all model outputs) |
| Feature Engineering | 78-dimensional CICIDS2018 feature vectors, robust z-score normalization |
| Training Data | Synthetic CICIDS2018 + UNSW-NB15 (60,000 samples, 12 attack classes) |
| Authentication | JWT (HS256) + bcrypt |
| Database | PostgreSQL 16 (SQLAlchemy ORM) |
| Cache / Queue | Redis 7 |
| Real-time | WebSocket (per-org broadcast) |
| Frontend | React 18, Axios |
| Container | Docker + Docker Compose |
| Proxy | Nginx (reverse proxy + SSL termination) |
| Threat Framework | MITRE ATT&CK (14 tactics, 17+ techniques) |
| Log Formats | Zeek TSV, Suricata EVE JSON, CSV, plain text |

---

## ML Architecture

### Ensemble Stack (Section 4.2 — Research Paper)

```
Network Flow
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

### ABRE — 3-Tier Approval Engine (Section 4.3 — Research Paper)

| Tier | Risk Level | Threat Score | Action |
|---|---|---|---|
| Tier 1 | Low | < 0.4 | Auto-execute response |
| Tier 2 | Medium | 0.4 – 0.75 | Analyst approval required |
| Tier 3 | High | > 0.75 | Manager approval required |

---

## Multi-Tenant SaaS Architecture

- Organization-isolated data — every query filtered by `organization_id`
- Role-based access control: `ADMIN` → `ANALYST` → `VIEWER`
- JWT access tokens (30 min) + refresh tokens (7 days)
- First user per organization auto-assigned ADMIN

---

## Real-Time Operations

- WebSocket endpoint (`/ws?token=<JWT>`) for live incident streaming
- Per-organization broadcast isolation
- Frontend auto-reconnects on disconnect
- Toast notifications on every new incident

---

## Dashboard

- Live connection status indicator (green / yellow / red)
- MITRE ATT&CK heatmap (14 tactics, color-coded by threat count)
- Incident timeline chart (last 10 days)
- Search + filter by risk level / status / attack category
- One-click Approve / Reject with role enforcement
- Per-incident: attack category, threat score, ABRE tier, AI reason

---

## System Architecture

```
Browser
  │
  └── Nginx (port 80/443)
        ├── /            → React SPA (static)
        ├── /api/*       → FastAPI backend (proxy)
        ├── /upload-logs → FastAPI backend (proxy, 50 MB limit)
        ├── /incidents   → FastAPI backend (proxy)
        └── /ws          → FastAPI WebSocket (proxy, keep-alive)

FastAPI
  ├── Auth endpoints  (/api/v1/auth/register, /login)
  ├── Upload endpoint (/upload-logs)
  │     ├── Zeek / Suricata / CSV / text parser
  │     ├── 78-feature extraction (CICIDS2018)
  │     ├── Ensemble inference (BiLSTM + XGBoost + IF + OC-SVM)
  │     ├── ABRE risk tier assignment
  │     └── MITRE ATT&CK mapping
  ├── Incidents CRUD  (/incidents, approve, reject)
  ├── WebSocket       (/ws)
  └── Metrics         (/metrics)

PostgreSQL  →  Organization, User, Incident tables
Redis       →  Session cache, rate limiting
```

---

## Running Locally

**Prerequisites:** Docker + Docker Compose

```bash
git clone https://github.com/roahanb/AI-Driven-Network-Detection-and-Response-SaaS-Platform-with-Approval-Based-Response-Engine.git
cd AI-Driven-Network-Detection-and-Response-SaaS-Platform-with-Approval-Based-Response-Engine

cp backend/.env.example backend/.env
# Edit backend/.env — set SECRET_KEY and DATABASE_URL

docker compose up -d --build
# Models train automatically during build (~3 min)
```

Open **http://localhost:3000** — register an account and upload a log file.

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | ✗ | Register user + org |
| POST | `/api/v1/auth/login` | ✗ | Login, returns JWT |
| POST | `/upload-logs` | ✓ | Upload + analyze log file |
| GET | `/incidents` | ✓ | List org incidents |
| PUT | `/incidents/{id}/approve` | ✓ ANALYST+ | Approve incident |
| PUT | `/incidents/{id}/reject` | ✓ ANALYST+ | Reject incident |
| GET | `/metrics` | ✓ | Platform counters |
| WS | `/ws?token=<JWT>` | ✓ | Real-time event stream |
| GET | `/health` | ✗ | Health check |

---

## Author

**Roahan B.**
[roahacks.com](https://roahacks.com)
