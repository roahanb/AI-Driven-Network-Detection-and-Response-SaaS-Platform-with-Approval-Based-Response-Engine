# AI-NDR — AI-Driven Network Detection and Response Platform

A production-ready, multi-tenant Network Detection and Response (NDR) platform with ML-based anomaly detection, MITRE ATT&CK mapping, real-time WebSocket streaming, and a human-in-the-loop approval workflow.

**Live at:** [roahacks.com](https://roahacks.com)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python 3.11) |
| ML Detection | scikit-learn Isolation Forest |
| Authentication | JWT (HS256) + bcrypt |
| Database | PostgreSQL 16 (SQLAlchemy ORM) |
| Cache / Queue | Redis 7 |
| Real-time | WebSocket (per-org broadcast) |
| Frontend | React 18, Axios |
| Container | Docker + Docker Compose |
| Proxy | Nginx (reverse proxy + SSL termination) |
| Threat Framework | MITRE ATT&CK (8 tactics, 17+ techniques) |
| Log Formats | Zeek TSV, Suricata EVE JSON, CSV, plain text |

---

## Features

### Detection Engine
- **Isolation Forest** — unsupervised anomaly detection across 5 network features (IP diversity, port entropy, domain entropy, byte ratio, time delta)
- **Rule-based engine** — 12 pattern-matching rules covering port scanning, DGA, data exfiltration, brute force, beaconing, and more
- **Shannon entropy** — detects DGA domains with threshold > 3.8
- **MITRE ATT&CK mapping** — every incident tagged with tactic + technique IDs at <5 ms

### Multi-Tenant SaaS Architecture
- Organization-isolated data — every query filtered by `organization_id`
- Role-based access control: `ADMIN` → `ANALYST` → `VIEWER`
- JWT access tokens (30 min) + refresh tokens (7 days)
- First user per organization auto-assigned ADMIN

### Real-Time Operations
- WebSocket endpoint (`/ws?token=<JWT>`) for live incident streaming
- Per-organization broadcast isolation
- Frontend auto-reconnects on disconnect

### Dashboard
- Live connection status indicator
- MITRE ATT&CK heatmap (14 tactics)
- Incident timeline chart (last 10 days)
- Search + filter by risk level / status
- One-click Approve / Reject with role enforcement
- Toast notifications for real-time events

---

## Architecture

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
  │     ├── Zeek/Suricata/CSV/text parser
  │     ├── Rule-based detection
  │     ├── Isolation Forest ML prediction
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
git clone https://github.com/roahan/ai-ndr-platform.git
cd ai-ndr-platform

cp backend/.env.example backend/.env
# Edit backend/.env — set SECRET_KEY and DATABASE_URL

docker-compose up -d --build
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

## Sample Log Files

`laptop_logs.txt` and `network_logs.txt` in the repo root can be uploaded directly to test detection.

---

## Author

**Roahan B.**
[roahacks.com](https://roahacks.com)
