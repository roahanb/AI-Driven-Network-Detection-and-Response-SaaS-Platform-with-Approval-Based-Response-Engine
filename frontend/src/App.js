import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import "./App.css";
import AICompanion from "./AICompanion";
import XDRWorkbench from "./XDRWorkbench";

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
    <div className="panel" style={{ marginBottom: 32, background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.12)" }}>
      <div className="panel-header">
        <div>
          <div className="eyebrow">Analytics</div>
          <h2>Incident Timeline</h2>
        </div>
      </div>
      <div style={{ background: "rgba(0, 0, 0, 0.3)", padding: 20, borderRadius: 12, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 10, height: 200, padding: "16px 8px" }}>
          {byDay.map(([day, counts]) => {
            const total = counts.high + counts.medium + counts.low;
            const heightPct = (total / maxVal) * 100;
            return (
              <div key={day} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
                <div style={{ width: "100%", height: `${Math.max(heightPct, 8)}%`, display: "flex", flexDirection: "column", justifyContent: "flex-end", minHeight: 8, background: "rgba(255,255,255,0.03)", borderRadius: 6, padding: 2 }}>
                  <div style={{ width: "100%", height: `${(counts.high / Math.max(total, 1)) * 100}%`, background: "#ff6b6b", borderRadius: "3px 3px 0 0", minHeight: counts.high > 0 ? 6 : 0, boxShadow: counts.high > 0 ? "0 0 8px rgba(255, 107, 107, 0.4)" : "none" }} />
                  <div style={{ width: "100%", height: `${(counts.medium / Math.max(total, 1)) * 100}%`, background: "#ffa94d", minHeight: counts.medium > 0 ? 6 : 0, boxShadow: counts.medium > 0 ? "0 0 6px rgba(255, 169, 77, 0.3)" : "none" }} />
                  <div style={{ width: "100%", height: `${(counts.low / Math.max(total, 1)) * 100}%`, background: "#51cf66", borderRadius: "0 0 3px 3px", minHeight: counts.low > 0 ? 6 : 0, boxShadow: counts.low > 0 ? "0 0 6px rgba(81, 207, 102, 0.3)" : "none" }} />
                </div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.7)", fontWeight: 500, whiteSpace: "nowrap" }}>{day.slice(5)}</div>
              </div>
            );
          })}
        </div>
      </div>
      <div style={{ display: "flex", gap: 20, padding: "0 8px" }}>
        {[["#ff6b6b", "High"], ["#ffa94d", "Medium"], ["#51cf66", "Low"]].map(([color, label]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "rgba(255,255,255,0.8)" }}>
            <div style={{ width: 12, height: 12, background: color, borderRadius: 3, boxShadow: `0 0 6px ${color}40` }} />
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
// Confirm Dialog (replaces browser popup)
// ─────────────────────────────────────────────
function ConfirmDialog({ title, message, onConfirm, onCancel }) {
  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 10000,
      background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div style={{
        background: "#1a1f2e", border: "1px solid rgba(255,100,100,0.3)",
        borderRadius: 14, padding: "28px 32px", maxWidth: 420, width: "90%",
        boxShadow: "0 20px 60px rgba(0,0,0,0.6)",
      }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: "white", marginBottom: 10 }}>{title}</div>
        <div style={{ fontSize: 14, color: "rgba(255,255,255,0.55)", marginBottom: 24, lineHeight: 1.6 }}>{message}</div>
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button onClick={onCancel} style={{
            padding: "9px 20px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.15)",
            background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.7)",
            cursor: "pointer", fontSize: 14,
          }}>Cancel</button>
          <button onClick={onConfirm} style={{
            padding: "9px 20px", borderRadius: 8, border: "1px solid rgba(255,80,80,0.5)",
            background: "rgba(255,80,80,0.15)", color: "#ff6b6b",
            cursor: "pointer", fontSize: 14, fontWeight: 600,
          }}>Delete All</button>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Human-readable incident title
// ─────────────────────────────────────────────
function friendlyTitle(alertType) {
  if (!alertType) return "Network Event";
  const a = alertType.toLowerCase();
  if (a.startsWith("dns-query:")) return "DNS Lookup: " + alertType.split(": ")[1];
  if (a.startsWith("tls:"))       return "Secure Connection: " + alertType.split(": ")[1];
  if (a.startsWith("http:"))      return "Web Request: " + alertType.split(": ")[1];
  if (a.startsWith("dns-query"))  return "DNS Lookup";
  if (a.includes("netflow:tcp"))  return "TCP Network Flow";
  if (a.includes("netflow:udp"))  return "UDP Network Flow";
  if (a.includes("flow:tcp"))     return "TCP Connection";
  if (a.includes("flow:udp"))     return "UDP Connection";
  if (a.includes("anomaly"))      return "Network Anomaly Detected";
  if (a.includes("portscan") || a.includes("port scan")) return "Port Scan Detected";
  if (a.includes("brute"))        return "Brute Force Attempt";
  if (a.includes("exploit"))      return "Exploit Attempt";
  if (a.includes("malware"))      return "Malware Communication";
  if (a.includes("ransomware"))   return "Ransomware Activity";
  if (a.includes("c2") || a.includes("beacon")) return "C2 Beacon Detected";
  if (a.includes("ddos") || a.includes("flood")) return "DDoS / Flood Attack";
  if (a.includes("ssh"))          return "SSH Activity";
  if (a.includes("ftp"))          return "FTP Activity";
  if (a.includes("dns"))          return "DNS Activity";
  // Capitalise whatever remains
  return alertType.replace(/[-_:]/g, " ").replace(/\b\w/g, c => c.toUpperCase());
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
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [liveNotifs, setLiveNotifs] = useState([]);
  const [watcherRunning, setWatcherRunning] = useState(false);
  const [watcherUptime, setWatcherUptime] = useState(null);
  const [watcherLoading, setWatcherLoading] = useState(false);
  const wsRef = useRef(null);

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

  // Poll watcher status every 5s
  const fetchWatcherStatus = useCallback(async () => {
    try {
      const res = await makeClient().get("/watcher/status");
      setWatcherRunning(res.data.running);
      setWatcherUptime(res.data.uptime);
    } catch (_) {}
  }, []);

  useEffect(() => {
    fetchWatcherStatus();
    const t = setInterval(fetchWatcherStatus, 5000);
    return () => clearInterval(t);
  }, [fetchWatcherStatus]);

  const toggleWatcher = async () => {
    setWatcherLoading(true);
    try {
      if (watcherRunning) {
        await makeClient().post("/watcher/stop");
        toast("Watcher stopped", "info");
      } else {
        await makeClient().post("/watcher/start");
        toast("Watcher started — monitoring live traffic", "success");
      }
      await fetchWatcherStatus();
    } catch (err) {
      toast(err.response?.data?.detail || "Watcher control failed", "error");
    } finally {
      setWatcherLoading(false);
    }
  };

  // WebSocket real-time connection
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    // In dev (port 3001) connect to backend directly on 8000; in prod use same host
    const wsHost = process.env.NODE_ENV === "development" ? "localhost:8000" : window.location.host;
    const wsUrl = `${protocol}//${wsHost}/ws?token=${token}`;

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
            const msg = JSON.parse(event.data);
            const evtType = msg.event || msg.type;
            const payload = msg.data || msg.payload || {};
            if (evtType === "incident_created" || evtType === "new_incidents") {
              const alertType = payload.alert_type || payload.incidents?.[0]?.alert_type || "event";
              const srcIp = payload.source_ip || payload.incidents?.[0]?.source_ip || "";
              const risk = payload.risk_level || payload.incidents?.[0]?.risk_level || "";
              const notif = { id: Date.now(), message: `New: ${alertType}${srcIp ? " from " + srcIp : ""}` };
              setLiveNotifs((prev) => [notif, ...prev].slice(0, 5));
              if (risk === "High") toast(`HIGH RISK: ${alertType}${srcIp ? " from " + srcIp : ""}`, "error");
              else if (risk === "Medium") toast(`Medium risk: ${alertType}`, "info");
              fetchIncidents();
            }
          } catch (_) {}
        };
      } catch (_) { setWsStatus("error"); }
    };

    connect();
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, [fetchIncidents, toast]);

  // Auto-poll every 5s as real-time fallback (ensures UI stays live even if WS drops)
  useEffect(() => {
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  // upload handler (kept for watcher API compatibility, not used in UI)
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

  // delete all incidents
  const deleteAllIncidents = () => setConfirmOpen(true);

  const confirmDelete = async () => {
    setConfirmOpen(false);
    try {
      setLoading(true);
      await makeClient().delete("/incidents");
      toast("All incidents deleted successfully", "success");
      await fetchIncidents();
    } catch (err) {
      if (err.response?.status === 403) toast("Only ADMIN users can delete incidents", "error");
      else toast(err.response?.data?.detail || "Delete failed", "error");
    } finally {
      setLoading(false);
    }
  };

  const downloadTodayLogs = () => {
    const today = new Date();
    const todayStr = today.toISOString().slice(0, 10);
    const todayIncidents = incidents.filter((i) => {
      if (!i.timestamp) return false;
      return new Date(i.timestamp).toISOString().slice(0, 10) === todayStr;
    });

    const high = todayIncidents.filter((i) => i.risk_level === "High");
    const medium = todayIncidents.filter((i) => i.risk_level === "Medium");
    const low = todayIncidents.filter((i) => i.risk_level === "Low");

    const fmt = (i) => [
      `  Incident #${i.id}`,
      `  Time      : ${i.timestamp ? new Date(i.timestamp).toLocaleString() : "N/A"}`,
      `  Alert     : ${i.alert_type || "N/A"}`,
      `  Source IP : ${i.source_ip || "N/A"}`,
      `  Dest IP   : ${i.destination_ip || "N/A"}`,
      `  Domain    : ${i.domain || "N/A"}`,
      `  Status    : ${i.status || "N/A"}`,
      `  MITRE     : ${i.mitre_tactic || "N/A"}${i.mitre_tactic_id ? ` (${i.mitre_tactic_id})` : ""}`,
      `  AI Score  : ${i.ai_score != null ? Number(i.ai_score).toFixed(4) : "N/A"}`,
      `  Summary   : ${i.summary || "N/A"}`,
      `  Action    : ${i.recommended_action || "N/A"}`,
      "",
    ].join("\n");

    const lines = [
      "═".repeat(70),
      `  NDR NETWORK ACTIVITY REPORT`,
      `  Date       : ${today.toDateString()}`,
      `  Generated  : ${today.toLocaleString()}`,
      `  Interface  : en0 (Suricata Live Monitor)`,
      "═".repeat(70),
      "",
      `SUMMARY`,
      `  Total Incidents Today : ${todayIncidents.length}`,
      `  High Risk             : ${high.length}`,
      `  Medium Risk           : ${medium.length}`,
      `  Low Risk              : ${low.length}`,
      "",
      "─".repeat(70),
      `HIGH RISK INCIDENTS (${high.length})`,
      "─".repeat(70),
      high.length === 0 ? "  None\n" : high.map(fmt).join("\n"),
      "─".repeat(70),
      `MEDIUM RISK INCIDENTS (${medium.length})`,
      "─".repeat(70),
      medium.length === 0 ? "  None\n" : medium.map(fmt).join("\n"),
      "─".repeat(70),
      `LOW RISK INCIDENTS (${low.length})`,
      "─".repeat(70),
      low.length === 0 ? "  None\n" : low.map(fmt).join("\n"),
      "═".repeat(70),
      `  END OF REPORT — roahacks.com NDR Platform`,
      "═".repeat(70),
    ];

    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `NDR_Report_${todayStr}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Downloaded report — ${todayIncidents.length} incidents`, "success");
  };

  const stats = useMemo(() => ({
    total: incidents.length,
    high: incidents.filter((i) => i.risk_level === "High").length,
    medium: incidents.filter((i) => i.risk_level === "Medium").length,
    low: incidents.filter((i) => i.risk_level === "Low").length,
    active: incidents.filter((i) => i.status === "Active").length,
    monitoring: incidents.filter((i) => i.status === "Monitoring").length,
    cleared: incidents.filter((i) => i.status === "Cleared").length,
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
      {confirmOpen && (
        <ConfirmDialog
          title="Delete All Incidents"
          message={`This will permanently remove all ${stats.total} incidents from the platform. Suricata will continue monitoring and new incidents will appear automatically.`}
          onConfirm={confirmDelete}
          onCancel={() => setConfirmOpen(false)}
        />
      )}
      <header className="hero">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: 3, textTransform: "uppercase", marginBottom: 6 }}>roahacks.com</div>
            <div className="hero-badge">AI-Driven Security Operations</div>
            <h1>Network Detection</h1>
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

        <p className="hero-subtitle">Real-time AI-powered network threat detection with Suricata live monitoring.</p>

        <div className="hero-actions" style={{ flexWrap: "wrap", gap: 10, alignItems: "center" }}>
          {/* Watcher Start/Stop control */}
          <div style={{
            flex: "1 1 200px", display: "flex", alignItems: "center",
            justifyContent: "space-between", gap: 12,
            background: watcherRunning ? "rgba(82,196,26,0.06)" : "rgba(255,255,255,0.04)",
            border: `1px solid ${watcherRunning ? "rgba(82,196,26,0.25)" : "rgba(255,255,255,0.1)"}`,
            borderRadius: 10, padding: "12px 18px", transition: "all 0.3s",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{
                width: 10, height: 10, borderRadius: "50%", flexShrink: 0,
                background: watcherRunning ? "#52c41a" : "rgba(255,255,255,0.25)",
                boxShadow: watcherRunning ? "0 0 10px #52c41a" : "none",
                animation: watcherRunning ? "pulse 1.5s infinite" : "none",
              }} />
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: "rgba(255,255,255,0.85)" }}>
                  Suricata · {watcherRunning ? "Live Monitoring" : "Stopped"}
                </div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>
                  {watcherRunning
                    ? `en0 · eve.json stream${watcherUptime ? " · up " + watcherUptime : ""}`
                    : "Click Start to begin network monitoring"}
                </div>
              </div>
            </div>
            {user.role === "ADMIN" && (
              <button
                onClick={toggleWatcher}
                disabled={watcherLoading}
                style={{
                  padding: "7px 18px", borderRadius: 8, fontSize: 13, fontWeight: 700,
                  cursor: watcherLoading ? "default" : "pointer",
                  border: watcherRunning ? "1px solid rgba(255,100,100,0.4)" : "1px solid rgba(82,196,26,0.4)",
                  background: watcherRunning ? "rgba(255,100,100,0.12)" : "rgba(82,196,26,0.12)",
                  color: watcherRunning ? "#ff6b6b" : "#52c41a",
                  transition: "all 0.2s", opacity: watcherLoading ? 0.6 : 1,
                  whiteSpace: "nowrap",
                }}
              >
                {watcherLoading ? "..." : watcherRunning ? "⏹ Stop" : "▶ Start"}
              </button>
            )}
          </div>

          {user.role === "ADMIN" && stats.total > 0 && (
            <button
              onClick={deleteAllIncidents}
              disabled={loading}
              style={{
                flex: "0 0 auto",
                padding: "12px 22px",
                borderRadius: 10,
                border: "1px solid rgba(255, 100, 100, 0.4)",
                background: "rgba(255, 100, 100, 0.1)",
                color: "#ff6b6b",
                fontSize: 15,
                fontWeight: 600,
                cursor: loading ? "default" : "pointer",
                transition: "all 0.2s",
                opacity: loading ? 0.55 : 1,
              }}
              onMouseEnter={(e) => {
                if (!loading) {
                  e.currentTarget.style.background = "rgba(255, 100, 100, 0.2)";
                  e.currentTarget.style.borderColor = "rgba(255, 100, 100, 0.6)";
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(255, 100, 100, 0.1)";
                e.currentTarget.style.borderColor = "rgba(255, 100, 100, 0.4)";
              }}
            >
              Delete All
            </button>
          )}
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
          ["Active", stats.active, "#ff6b6b"],
          ["Monitoring", stats.monitoring, "#faad14"],
        ].map(([label, val, color]) => (
          <div className="stat-card" key={label}>
            <div className="stat-label">{label}</div>
            <div className="stat-value" style={{ color }}>{val}</div>
          </div>
        ))}
      </section>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24, borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
        {[["workbench", "XDR Workbench"], ["incidents", "Incidents"], ["heatmap", "MITRE Heatmap"], ["analytics", "Analytics"]].map(([key, label]) => (
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

      {activeTab === "workbench" && <XDRWorkbench />}
      {activeTab === "heatmap" && <MitreHeatmap incidents={incidents} />}
      {activeTab === "analytics" && <RiskTimeline incidents={incidents} />}

      {activeTab === "incidents" && (
        <section className="panel">
          <div className="panel-header" style={{ flexWrap: "wrap", gap: 12 }}>
            <div>
              <div className="eyebrow">Operations Console</div>
              <h2>Detected Incidents</h2>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <input
                placeholder="Search IP, alert, domain..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ padding: "7px 12px", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 6, background: "rgba(255,255,255,0.06)", color: "white", fontSize: 13, width: 220 }}
              />
              {["all", "high", "medium", "low", "active", "monitoring", "cleared"].map((f) => (
                <button key={f} onClick={() => setFilter(f)} style={{
                  padding: "6px 12px", borderRadius: 20, fontSize: 12, cursor: "pointer",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: filter === f ? "rgba(100,180,255,0.25)" : "rgba(255,255,255,0.05)",
                  color: filter === f ? "white" : "rgba(255,255,255,0.5)",
                }}>
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
              <button
                onClick={downloadTodayLogs}
                style={{
                  padding: "7px 14px", borderRadius: 8, fontSize: 13, cursor: "pointer", fontWeight: 600,
                  border: "1px solid rgba(100,220,180,0.4)",
                  background: "rgba(100,220,180,0.1)",
                  color: "rgba(100,220,180,1)",
                  transition: "all 0.2s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(100,220,180,0.2)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(100,220,180,0.1)"; }}
                title="Download today's network activity report"
              >
                ↓ Download Today's Report
              </button>
            </div>
          </div>

          {/* High Alert Banner */}
          {incidents.filter((i) => i.risk_level === "High").length > 0 && (
            <div style={{
              margin: "0 0 20px 0",
              border: "1px solid rgba(255,77,79,0.5)",
              borderRadius: 10,
              background: "rgba(255,77,79,0.07)",
              padding: "14px 18px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ff4d4f", boxShadow: "0 0 10px #ff4d4f", animation: "pulse 1.5s infinite" }} />
                <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: "0.1em", color: "#ff4d4f", textTransform: "uppercase" }}>
                  High Risk Alerts — {incidents.filter((i) => i.risk_level === "High").length} Active
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {incidents.filter((i) => i.risk_level === "High").map((inc) => (
                  <div key={inc.id} style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8,
                    background: "rgba(255,77,79,0.08)", border: "1px solid rgba(255,77,79,0.25)",
                    borderRadius: 8, padding: "10px 14px",
                  }}>
                    <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 12, color: "rgba(255,255,255,0.45)" }}>#{inc.id}</span>
                      <span style={{ fontSize: 13, fontWeight: 600, color: "white" }}>{friendlyTitle(inc.alert_type)}</span>
                      <span style={{ fontSize: 12, color: "rgba(255,180,180,0.8)" }}>{inc.source_ip || "N/A"} → {inc.destination_ip || "N/A"}</span>
                      {inc.mitre_tactic && <span style={{ fontSize: 11, color: "rgba(100,200,255,0.7)", background: "rgba(100,200,255,0.1)", padding: "2px 7px", borderRadius: 4 }}>{inc.mitre_tactic}</span>}
                    </div>
                    <span style={{ fontSize: 11, color: "rgba(255,255,255,0.35)" }}>
                      {inc.timestamp ? new Date(inc.timestamp).toLocaleTimeString() : "N/A"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {filtered.length === 0 ? (
            <div className="empty-state">
              <h3>{incidents.length === 0 ? "No incidents yet" : "No matching incidents"}</h3>
              <p>{incidents.length === 0 ? "Suricata is monitoring your network. Incidents will appear automatically." : "Try adjusting your filters."}</p>
            </div>
          ) : (
            <div className="incident-grid">
              {filtered.map((incident) => (
                <article className="incident-card" key={incident.id}>
                  <div className="incident-top">
                    <div>
                      <div className="incident-id">Incident #{incident.id}</div>
                      <div className="incident-title">{friendlyTitle(incident.alert_type)}</div>
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
      {isAuthenticated && <AICompanion />}
    </>
  );
}

export default App;
