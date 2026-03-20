import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import "./App.css";

// Dev (npm start) → hit backend directly
// Docker / Production (nginx) → relative URL, nginx proxies to backend
const API_BASE = process.env.NODE_ENV === "development" ? "http://localhost:8000" : "";

// ─────────────────────────────────────────────
// Axios client factory
// ─────────────────────────────────────────────
function makeClient() {
  const token = localStorage.getItem("access_token");
  return axios.create({
    baseURL: API_BASE,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

// ─────────────────────────────────────────────
// Toast notification component
// ─────────────────────────────────────────────
function Toast({ toasts, onDismiss }) {
  return (
    <div style={{ position: "fixed", top: 20, right: 20, zIndex: 9999, display: "flex", flexDirection: "column", gap: 8 }}>
      {toasts.map((t) => (
        <div
          key={t.id}
          onClick={() => onDismiss(t.id)}
          style={{
            background: t.type === "error" ? "rgba(220,50,50,0.95)" : t.type === "success" ? "rgba(30,180,100,0.95)" : "rgba(40,100,220,0.95)",
            color: "white",
            padding: "12px 18px",
            borderRadius: 8,
            fontSize: 14,
            maxWidth: 320,
            cursor: "pointer",
            boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
          }}
        >
          <strong>{t.type === "error" ? "⚠ " : t.type === "success" ? "✓ " : "⚡ "}</strong>
          {t.message}
        </div>
      ))}
    </div>
  );
}

function useToast() {
  const [toasts, setToasts] = useState([]);
  const add = useCallback((message, type = "info") => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  }, []);
  const dismiss = useCallback((id) => setToasts((prev) => prev.filter((t) => t.id !== id)), []);
  return { toasts, add, dismiss };
}

// ─────────────────────────────────────────────
// MITRE ATT&CK Heatmap
// ─────────────────────────────────────────────
const MITRE_TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

function MitreHeatmap({ incidents }) {
  const counts = useMemo(() => {
    const map = {};
    MITRE_TACTICS.forEach((t) => (map[t] = 0));
    incidents.forEach((i) => {
      if (i.mitre_tactic && map[i.mitre_tactic] !== undefined) {
        map[i.mitre_tactic]++;
      }
    });
    return map;
  }, [incidents]);

  const maxCount = Math.max(...Object.values(counts), 1);

  return (
    <div style={{ marginBottom: 32 }}>
      <div className="panel-header">
        <div>
          <div className="eyebrow">Threat Intelligence</div>
          <h2>MITRE ATT&amp;CK Coverage</h2>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 8 }}>
        {MITRE_TACTICS.map((tactic) => {
          const count = counts[tactic];
          const intensity = count / maxCount;
          const bg = count === 0
            ? "rgba(255,255,255,0.04)"
            : `rgba(255,${Math.round(80 - intensity * 60)},${Math.round(80 - intensity * 60)},${0.3 + intensity * 0.6})`;
          return (
            <div
              key={tactic}
              style={{
                background: bg,
                border: `1px solid ${count > 0 ? "rgba(255,100,100,0.4)" : "rgba(255,255,255,0.08)"}`,
                borderRadius: 8,
                padding: "12px 10px",
                textAlign: "center",
              }}
            >
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.6)", marginBottom: 4 }}>{tactic}</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: count > 0 ? "#ff6b6b" : "rgba(255,255,255,0.3)" }}>
                {count}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Risk Timeline Chart
// ─────────────────────────────────────────────
function RiskTimeline({ incidents }) {
  const byDay = useMemo(() => {
    const map = {};
    incidents.forEach((i) => {
      const day = i.timestamp ? String(i.timestamp).substring(0, 10) : "Unknown";
      if (!map[day]) map[day] = { high: 0, medium: 0, low: 0 };
      const r = (i.risk_level || "").toLowerCase();
      if (r === "high") map[day].high++;
      else if (r === "medium") map[day].medium++;
      else map[day].low++;
    });
    return Object.entries(map).sort(([a], [b]) => a.localeCompare(b)).slice(-10);
  }, [incidents]);

  if (byDay.length === 0) return (
    <div className="empty-state"><h3>No timeline data</h3><p>Upload logs to see analytics.</p></div>
  );

  const maxVal = Math.max(...byDay.map(([, v]) => v.high + v.medium + v.low), 1);

  return (
    <div className="panel" style={{ marginBottom: 32 }}>
      <div className="panel-header">
        <div>
          <div className="eyebrow">Analytics</div>
          <h2>Incident Timeline</h2>
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 8, height: 120, padding: "0 8px" }}>
        {byDay.map(([day, counts]) => {
          const total = counts.high + counts.medium + counts.low;
          const heightPct = (total / maxVal) * 100;
          return (
            <div key={day} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
              <div style={{ width: "100%", height: `${heightPct}%`, display: "flex", flexDirection: "column", justifyContent: "flex-end", minHeight: 4 }}>
                <div style={{ width: "100%", height: `${(counts.high / Math.max(total, 1)) * 100}%`, background: "#ff4d4f", borderRadius: "4px 4px 0 0", minHeight: counts.high > 0 ? 4 : 0 }} />
                <div style={{ width: "100%", height: `${(counts.medium / Math.max(total, 1)) * 100}%`, background: "#faad14", minHeight: counts.medium > 0 ? 4 : 0 }} />
                <div style={{ width: "100%", height: `${(counts.low / Math.max(total, 1)) * 100}%`, background: "#52c41a", borderRadius: "0 0 4px 4px", minHeight: counts.low > 0 ? 4 : 0 }} />
              </div>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", transform: "rotate(-45deg)", whiteSpace: "nowrap" }}>{day.slice(5)}</div>
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 16, marginTop: 12, padding: "0 8px" }}>
        {[["#ff4d4f", "High"], ["#faad14", "Medium"], ["#52c41a", "Low"]].map(([color, label]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "rgba(255,255,255,0.6)" }}>
            <div style={{ width: 10, height: 10, background: color, borderRadius: 2 }} />
            {label}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Login Page
// ─────────────────────────────────────────────
function LoginPage({ onLoginSuccess, toast }) {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const endpoint = isRegister ? "/api/v1/auth/register" : "/api/v1/auth/login";
      const payload = isRegister ? { email, password, organization_name: orgName } : { email, password };
      const response = await axios.post(`${API_BASE}${endpoint}`, payload);
      localStorage.setItem("access_token", response.data.access_token);
      localStorage.setItem("refresh_token", response.data.refresh_token);
      localStorage.setItem("user_email", response.data.user.email);
      localStorage.setItem("user_role", response.data.user.role);
      localStorage.setItem("org_name", response.data.user.organization || orgName);
      onLoginSuccess();
    } catch (error) {
      toast(error.response?.data?.detail || "Authentication failed", "error");
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    padding: "12px 14px",
    border: "1px solid rgba(255,255,255,0.15)",
    borderRadius: 8,
    background: "rgba(255,255,255,0.06)",
    color: "white",
    fontSize: 15,
    width: "100%",
    boxSizing: "border-box",
    outline: "none",
  };

  return (
    <div className="page">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <div style={{ maxWidth: 420, margin: "80px auto", padding: "0 20px" }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", letterSpacing: 3, textTransform: "uppercase", marginBottom: 12 }}>
            roahacks.com
          </div>
          <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>AI-NDR Platform</h1>
          <p style={{ color: "rgba(255,255,255,0.5)", fontSize: 15 }}>
            {isRegister ? "Create your organization account" : "Sign in to your dashboard"}
          </p>
        </div>

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <input type="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} required style={inputStyle} />
          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required style={inputStyle} />
          {isRegister && (
            <input type="text" placeholder="Organization name" value={orgName} onChange={(e) => setOrgName(e.target.value)} required style={inputStyle} />
          )}
          <button type="submit" disabled={loading} className="primary-btn" style={{ marginTop: 8, padding: "12px", fontSize: 15 }}>
            {loading ? "Please wait..." : isRegister ? "Create Account" : "Sign In"}
          </button>
        </form>

        <p style={{ textAlign: "center", marginTop: 20, color: "rgba(255,255,255,0.5)", fontSize: 14 }}>
          {isRegister ? "Already have an account? " : "Don't have an account? "}
          <button onClick={() => setIsRegister(!isRegister)} style={{ background: "none", border: "none", color: "rgba(100,180,255,1)", cursor: "pointer", textDecoration: "underline", fontSize: 14 }}>
            {isRegister ? "Sign In" : "Register free"}
          </button>
        </p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Dashboard Page
// ─────────────────────────────────────────────
function DashboardPage({ user, onLogout, toast }) {
  const [file, setFile] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [wsStatus, setWsStatus] = useState("disconnected");
  const [activeTab, setActiveTab] = useState("incidents");
  const [liveNotifs, setLiveNotifs] = useState([]);
  const wsRef = useRef(null);
  const fileInputRef = useRef(null);

  // fetch incidents
  const fetchIncidents = useCallback(async () => {
    try {
      const res = await makeClient().get("/incidents");
      setIncidents(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      if (err.response?.status === 401) onLogout();
    }
  }, [onLogout]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  // WebSocket real-time connection
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws?token=${token}`;

    const connect = () => {
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;
        ws.onopen = () => setWsStatus("connected");
        ws.onclose = () => {
          setWsStatus("disconnected");
          setTimeout(connect, 5000);
        };
        ws.onerror = () => setWsStatus("error");
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "incident_created") {
              const notif = { id: Date.now(), message: `New incident: ${data.payload?.alert_type} from ${data.payload?.source_ip}` };
              setLiveNotifs((prev) => [notif, ...prev].slice(0, 5));
              toast(`New ${data.payload?.risk_level} risk incident detected`, "info");
              fetchIncidents();
            } else if (data.type === "incident_approved") {
              toast(`Incident #${data.payload?.incident_id} approved`, "success");
              fetchIncidents();
            } else if (data.type === "incident_rejected") {
              toast(`Incident #${data.payload?.incident_id} rejected`, "info");
              fetchIncidents();
            }
          } catch (_) {}
        };
      } catch (_) { setWsStatus("error"); }
    };

    connect();
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, [fetchIncidents, toast]);

  // upload handler
  const handleUpload = async () => {
    if (!file) { toast("Please select a log file first", "error"); return; }
    const formData = new FormData();
    formData.append("file", file);
    try {
      setLoading(true);
      const res = await makeClient().post("/upload-logs", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      toast(`${res.data.message} — ${res.data.incidents_found} incidents found`, "success");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
      await fetchIncidents();
    } catch (err) {
      toast(err.response?.data?.detail || "Upload failed", "error");
    } finally {
      setLoading(false);
    }
  };

  // approve / reject
  const updateStatus = async (id, action) => {
    try {
      await makeClient().put(`/incidents/${id}/${action}`);
      await fetchIncidents();
    } catch (err) {
      if (err.response?.status === 403) toast("Insufficient permissions", "error");
      else toast("Action failed", "error");
    }
  };

  const stats = useMemo(() => ({
    total: incidents.length,
    high: incidents.filter((i) => i.risk_level === "High").length,
    medium: incidents.filter((i) => i.risk_level === "Medium").length,
    low: incidents.filter((i) => i.risk_level === "Low").length,
    pending: incidents.filter((i) => i.status === "Pending").length,
    approved: incidents.filter((i) => i.status === "Approved").length,
    rejected: incidents.filter((i) => i.status === "Rejected").length,
  }), [incidents]);

  const filtered = useMemo(() => {
    let list = incidents;
    if (filter !== "all") list = list.filter((i) =>
      (i.risk_level || "").toLowerCase() === filter ||
      (i.status || "").toLowerCase() === filter
    );
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((i) =>
        (i.source_ip || "").includes(q) ||
        (i.destination_ip || "").includes(q) ||
        (i.alert_type || "").toLowerCase().includes(q) ||
        (i.domain || "").toLowerCase().includes(q) ||
        (i.mitre_tactic || "").toLowerCase().includes(q)
      );
    }
    return list;
  }, [incidents, filter, search]);

  const getRiskClass = (r) => r === "High" ? "pill pill-high" : r === "Medium" ? "pill pill-medium" : "pill pill-low";
  const getStatusClass = (s) => s === "Approved" ? "pill pill-approved" : s === "Rejected" ? "pill pill-rejected" : "pill pill-pending";
  const wsColor = wsStatus === "connected" ? "#52c41a" : wsStatus === "error" ? "#ff4d4f" : "#faad14";

  return (
    <div className="page">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      {/* Header */}
      <header className="hero">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: 3, textTransform: "uppercase", marginBottom: 6 }}>roahacks.com</div>
            <div className="hero-badge">AI-Driven Security Operations</div>
            <h1>Network Detection &amp; Response</h1>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 8 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: wsColor, boxShadow: `0 0 8px ${wsColor}` }} />
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>
                {wsStatus === "connected" ? "Live" : wsStatus === "error" ? "WS Error" : "Connecting..."}
              </span>
            </div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.6)" }}>
              {user.email} · <span style={{ color: "rgba(100,180,255,0.8)" }}>{user.role}</span>
            </div>
            <button onClick={onLogout} style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.15)", color: "rgba(255,255,255,0.7)", padding: "5px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13 }}>
              Sign Out
            </button>
          </div>
        </div>

        <p className="hero-subtitle">Enterprise-grade incident visibility with AI triage and human approval workflows.</p>

        <div className="hero-actions" style={{ flexWrap: "wrap", gap: 10 }}>
          <label className="file-picker" style={{ flex: "1 1 200px" }}>
            <span>{file ? file.name : "Choose log file (.txt, .csv, .json, .log)"}</span>
            <input ref={fileInputRef} type="file" accept=".txt,.log,.csv,.json" onChange={(e) => setFile(e.target.files[0])} />
          </label>
          <button className="primary-btn" onClick={handleUpload} disabled={loading} style={{ flex: "0 0 auto" }}>
            {loading ? "Uploading..." : "Upload & Analyze"}
          </button>
        </div>

        {liveNotifs.length > 0 && (
          <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
            {liveNotifs.map((n) => (
              <div key={n.id} style={{ background: "rgba(255,100,50,0.15)", border: "1px solid rgba(255,100,50,0.3)", borderRadius: 6, padding: "4px 10px", fontSize: 12, color: "rgba(255,180,150,1)" }}>
                ⚡ {n.message}
              </div>
            ))}
          </div>
        )}
      </header>

      {/* Stats */}
      <section className="stats-grid">
        {[
          ["Total", stats.total, "#fff"],
          ["High Risk", stats.high, "#ff4d4f"],
          ["Medium", stats.medium, "#faad14"],
          ["Low", stats.low, "#52c41a"],
          ["Pending", stats.pending, "#a0a0ff"],
          ["Approved", stats.approved, "#52c41a"],
        ].map(([label, val, color]) => (
          <div className="stat-card" key={label}>
            <div className="stat-label">{label}</div>
            <div className="stat-value" style={{ color }}>{val}</div>
          </div>
        ))}
      </section>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24, borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
        {[["incidents", "Incidents"], ["heatmap", "MITRE Heatmap"], ["analytics", "Analytics"]].map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)} style={{
            background: "none", border: "none",
            color: activeTab === key ? "white" : "rgba(255,255,255,0.45)",
            fontSize: 15, fontWeight: activeTab === key ? 600 : 400,
            padding: "10px 18px", cursor: "pointer",
            borderBottom: activeTab === key ? "2px solid rgba(100,180,255,0.8)" : "2px solid transparent",
            marginBottom: -1,
          }}>
            {label}
          </button>
        ))}
      </div>

      {activeTab === "heatmap" && <MitreHeatmap incidents={incidents} />}
      {activeTab === "analytics" && <RiskTimeline incidents={incidents} />}

      {activeTab === "incidents" && (
        <section className="panel">
          <div className="panel-header" style={{ flexWrap: "wrap", gap: 12 }}>
            <div>
              <div className="eyebrow">Operations Console</div>
              <h2>Detected Incidents</h2>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input
                placeholder="Search IP, alert, domain..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ padding: "7px 12px", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 6, background: "rgba(255,255,255,0.06)", color: "white", fontSize: 13, width: 220 }}
              />
              {["all", "high", "medium", "low", "pending", "approved"].map((f) => (
                <button key={f} onClick={() => setFilter(f)} style={{
                  padding: "6px 12px", borderRadius: 20, fontSize: 12, cursor: "pointer",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: filter === f ? "rgba(100,180,255,0.25)" : "rgba(255,255,255,0.05)",
                  color: filter === f ? "white" : "rgba(255,255,255,0.5)",
                }}>
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="empty-state">
              <h3>{incidents.length === 0 ? "No incidents yet" : "No matching incidents"}</h3>
              <p>{incidents.length === 0 ? "Upload a log file to start detection." : "Try adjusting your filters."}</p>
            </div>
          ) : (
            <div className="incident-grid">
              {filtered.map((incident) => (
                <article className="incident-card" key={incident.id}>
                  <div className="incident-top">
                    <div>
                      <div className="incident-id">Incident #{incident.id}</div>
                      <div className="incident-title">{incident.alert_type || "Unknown alert"}</div>
                    </div>
                    <div className="badge-stack">
                      <span className={getRiskClass(incident.risk_level)}>{incident.risk_level || "N/A"}</span>
                      <span className={getStatusClass(incident.status)}>{incident.status || "Pending"}</span>
                    </div>
                  </div>

                  <div className="meta-grid">
                    <div className="meta-item">
                      <span className="meta-label">Source</span>
                      <span className="meta-value">{incident.source_ip || "N/A"}</span>
                    </div>
                    <div className="meta-item">
                      <span className="meta-label">Destination</span>
                      <span className="meta-value">{incident.destination_ip || "N/A"}</span>
                    </div>
                    <div className="meta-item">
                      <span className="meta-label">Domain</span>
                      <span className="meta-value">{incident.domain || "N/A"}</span>
                    </div>
                    <div className="meta-item">
                      <span className="meta-label">Time</span>
                      <span className="meta-value">{incident.timestamp ? new Date(incident.timestamp).toLocaleString() : "N/A"}</span>
                    </div>
                  </div>

                  <div className="summary-box">
                    <div className="section-label">Summary</div>
                    <p>{incident.summary || "No summary available."}</p>
                  </div>

                  <div className="action-box">
                    <div className="section-label">Recommended Action</div>
                    <p>{incident.recommended_action || "No action available."}</p>
                  </div>

                  {incident.mitre_tactic && (
                    <div style={{ padding: "10px 12px", background: "rgba(100,200,255,0.08)", border: "1px solid rgba(100,200,255,0.2)", borderRadius: 6, marginBottom: 10 }}>
                      <div className="section-label">MITRE ATT&amp;CK</div>
                      <div style={{ fontSize: 13, color: "rgba(255,255,255,0.75)", marginTop: 4 }}>
                        <span style={{ color: "rgba(100,200,255,0.9)", fontWeight: 600 }}>{incident.mitre_tactic}</span>
                        {incident.mitre_tactic_id && <span style={{ color: "rgba(255,255,255,0.4)", marginLeft: 4 }}>({incident.mitre_tactic_id})</span>}
                        {incident.mitre_technique && (
                          <div style={{ marginTop: 2 }}>
                            {incident.mitre_technique}
                            {incident.mitre_technique_id && <span style={{ color: "rgba(255,255,255,0.4)", marginLeft: 4 }}>({incident.mitre_technique_id})</span>}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="ai-box">
                    <div className="ai-header">
                      <span className="section-label">AI Analysis</span>
                      <span className="ai-score">Score {incident.ai_score != null ? Number(incident.ai_score).toFixed(4) : "N/A"}</span>
                    </div>
                    <div className="ai-prediction-row">
                      <span className="meta-label">Prediction</span>
                      <span className="meta-value">{incident.ai_prediction || "N/A"}</span>
                    </div>
                    <p className="ai-reason">{incident.ai_reason || "No AI explanation available."}</p>
                  </div>

                  {user.role !== "VIEWER" && (
                    <div className="button-row">
                      <button className="ghost-btn approve-btn" onClick={() => updateStatus(incident.id, "approve")} disabled={incident.status !== "Pending"}>
                        Approve
                      </button>
                      <button className="ghost-btn reject-btn" onClick={() => updateStatus(incident.id, "reject")} disabled={incident.status !== "Pending"}>
                        Reject
                      </button>
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────
// App root
// ─────────────────────────────────────────────
function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const { toasts, add: addToast, dismiss } = useToast();

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    const email = localStorage.getItem("user_email");
    const role = localStorage.getItem("user_role");
    if (token && email && role) {
      setUser({ email, role });
      setIsAuthenticated(true);
    }
    setReady(true);
  }, []);

  const handleLoginSuccess = () => {
    setUser({ email: localStorage.getItem("user_email"), role: localStorage.getItem("user_role") });
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    ["access_token", "refresh_token", "user_email", "user_role", "org_name"].forEach((k) => localStorage.removeItem(k));
    setIsAuthenticated(false);
    setUser(null);
  };

  if (!ready) return <div style={{ color: "white", textAlign: "center", paddingTop: 80 }}>Loading...</div>;

  return (
    <>
      <Toast toasts={toasts} onDismiss={dismiss} />
      {isAuthenticated
        ? <DashboardPage user={user} onLogout={handleLogout} toast={addToast} />
        : <LoginPage onLoginSuccess={handleLoginSuccess} toast={addToast} />
      }
    </>
  );
}

export default App;
