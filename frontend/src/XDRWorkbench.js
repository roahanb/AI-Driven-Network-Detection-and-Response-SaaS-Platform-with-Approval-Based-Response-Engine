// XDR Workbench — Trend Micro Vision One-style unified triage
import React, { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API_BASE = process.env.NODE_ENV === "development" ? "http://localhost:8000" : "";

function makeClient() {
  const token = localStorage.getItem("access_token");
  return axios.create({
    baseURL: API_BASE,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
const riskColor = (r) =>
  r === "High" ? "#ff4d4f" : r === "Medium" ? "#faad14" : r === "Low" ? "#52c41a" : "#888";

const riskBg = (r) =>
  r === "High"
    ? "rgba(255,77,79,0.12)"
    : r === "Medium"
    ? "rgba(250,173,20,0.12)"
    : r === "Low"
    ? "rgba(82,196,26,0.12)"
    : "rgba(255,255,255,0.05)";

function Pill({ children, color = "#888", bg = "rgba(255,255,255,0.05)" }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 10,
        background: bg,
        color,
        fontSize: 11,
        fontWeight: 600,
        border: `1px solid ${color}40`,
      }}
    >
      {children}
    </span>
  );
}

// ─────────────────────────────────────────────
// Main workbench view
// ─────────────────────────────────────────────
export default function XDRWorkbench({ onOpenAICompanion }) {
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [error, setError] = useState(null);

  const fetchOverview = useCallback(async () => {
    try {
      setLoading(true);
      const res = await makeClient().get("/api/v1/xdr/workbench");
      setOverview(res.data);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load workbench");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();
    const t = setInterval(fetchOverview, 10000);
    return () => clearInterval(t);
  }, [fetchOverview]);

  if (loading && !overview) {
    return (
      <div style={{ padding: 40, textAlign: "center", color: "rgba(255,255,255,0.5)" }}>
        Loading XDR Workbench...
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          padding: 20,
          background: "rgba(255,77,79,0.1)",
          border: "1px solid rgba(255,77,79,0.3)",
          borderRadius: 8,
          color: "#ff6b6b",
        }}
      >
        {error}
      </div>
    );
  }

  if (!overview) return null;

  return (
    <div style={{ paddingBottom: 40 }}>
      {/* KPI strip */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
          gap: 10,
          marginBottom: 24,
        }}
      >
        {[
          ["Total Incidents", overview.total_incidents, "#fff"],
          ["Open", overview.open_incidents, "#faad14"],
          ["High Risk", overview.high_risk_count, "#ff4d4f"],
          ["Source IPs", overview.unique_source_ips, "#64b4ff"],
          ["Destinations", overview.unique_destinations, "#aa78ff"],
          ["Correlations", overview.correlation_clusters.length, "#78ffaa"],
        ].map(([label, val, c]) => (
          <div
            key={label}
            style={{
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 10,
              padding: "14px 16px",
            }}
          >
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", letterSpacing: 1, textTransform: "uppercase" }}>
              {label}
            </div>
            <div style={{ fontSize: 26, fontWeight: 700, color: c, marginTop: 4 }}>{val}</div>
          </div>
        ))}
      </div>

      {/* Two-column layout */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Top Assets */}
        <section
          style={{
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 12,
            padding: 18,
          }}
        >
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", letterSpacing: 1.5, textTransform: "uppercase" }}>
              Asset Risk
            </div>
            <h3 style={{ margin: "4px 0 0", fontSize: 17, color: "white" }}>
              Top Assets at Risk
            </h3>
          </div>
          {overview.top_assets.length === 0 ? (
            <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 13, padding: 10 }}>
              No asset data yet.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {overview.top_assets.map((a) => (
                <div
                  key={a.ip}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "10px 12px",
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid rgba(255,255,255,0.06)",
                    borderRadius: 8,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 13,
                        fontFamily: "ui-monospace, monospace",
                        color: "white",
                        fontWeight: 600,
                        marginBottom: 3,
                      }}
                    >
                      {a.ip}
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <Pill color="rgba(255,255,255,0.6)">{a.role}</Pill>
                      <Pill color="rgba(255,255,255,0.6)">{a.incident_count} incidents</Pill>
                      {a.high_risk_count > 0 && (
                        <Pill color="#ff4d4f" bg="rgba(255,77,79,0.1)">
                          {a.high_risk_count} high
                        </Pill>
                      )}
                      {a.mitre_tactics.slice(0, 2).map((t) => (
                        <Pill key={t} color="#64b4ff" bg="rgba(100,180,255,0.1)">
                          {t}
                        </Pill>
                      ))}
                    </div>
                  </div>
                  <div style={{ marginLeft: 12, textAlign: "right" }}>
                    <div
                      style={{
                        fontSize: 20,
                        fontWeight: 700,
                        color:
                          a.risk_score >= 60
                            ? "#ff4d4f"
                            : a.risk_score >= 30
                            ? "#faad14"
                            : "#52c41a",
                      }}
                    >
                      {a.risk_score}
                    </div>
                    <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)" }}>risk</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Correlation Clusters */}
        <section
          style={{
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 12,
            padding: 18,
          }}
        >
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", letterSpacing: 1.5, textTransform: "uppercase" }}>
              Correlation Engine
            </div>
            <h3 style={{ margin: "4px 0 0", fontSize: 17, color: "white" }}>
              Detected Attack Clusters
            </h3>
          </div>
          {overview.correlation_clusters.length === 0 ? (
            <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 13, padding: 10 }}>
              No correlations detected yet. Clusters appear when 2+ incidents share IPs or MITRE tactics.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {overview.correlation_clusters.map((c) => (
                <div
                  key={c.cluster_id}
                  onClick={() => c.incident_ids[0] && setSelectedIncidentId(c.incident_ids[0])}
                  style={{
                    padding: "10px 12px",
                    background: riskBg(c.highest_risk),
                    border: `1px solid ${riskColor(c.highest_risk)}40`,
                    borderRadius: 8,
                    cursor: "pointer",
                    transition: "transform 0.15s",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = "translateX(3px)")}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = "translateX(0)")}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: "white" }}>
                      {patternLabel(c.pattern)}: {c.pivot_value}
                    </span>
                    <Pill color={riskColor(c.highest_risk)} bg={riskBg(c.highest_risk)}>
                      {c.highest_risk || "—"}
                    </Pill>
                  </div>
                  <div style={{ fontSize: 11, color: "rgba(255,255,255,0.55)" }}>
                    {c.incident_count} linked incidents
                    {c.mitre_tactics.length > 0 && " · " + c.mitre_tactics.join(", ")}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* MITRE coverage strip */}
      {Object.keys(overview.mitre_coverage).length > 0 && (
        <section
          style={{
            marginTop: 20,
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 12,
            padding: 18,
          }}
        >
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", letterSpacing: 1.5, textTransform: "uppercase" }}>
              ATT&amp;CK Matrix
            </div>
            <h3 style={{ margin: "4px 0 0", fontSize: 17, color: "white" }}>
              MITRE Coverage (Observed)
            </h3>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(overview.mitre_coverage)
              .sort(([, a], [, b]) => b - a)
              .map(([tactic, count]) => (
                <div
                  key={tactic}
                  style={{
                    background: "rgba(100,180,255,0.08)",
                    border: "1px solid rgba(100,180,255,0.25)",
                    borderRadius: 6,
                    padding: "6px 12px",
                    fontSize: 12,
                    color: "rgba(180,210,255,0.95)",
                  }}
                >
                  {tactic}{" "}
                  <span style={{ color: "white", fontWeight: 700, marginLeft: 4 }}>{count}</span>
                </div>
              ))}
          </div>
        </section>
      )}

      {/* Incident drawer */}
      {selectedIncidentId && (
        <IncidentDrawer
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
          onAskAI={() => {
            if (onOpenAICompanion) onOpenAICompanion(selectedIncidentId);
          }}
        />
      )}
    </div>
  );
}

function patternLabel(p) {
  return (
    {
      same_source_ip: "Source",
      same_destination: "Destination",
      same_mitre_tactic: "MITRE Tactic",
    }[p] || p
  );
}

// ─────────────────────────────────────────────
// Incident Detail Drawer
// ─────────────────────────────────────────────
function IncidentDrawer({ incidentId, onClose, onAskAI }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checklist, setChecklist] = useState([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const res = await makeClient().get(`/api/v1/xdr/incidents/${incidentId}`);
        if (cancelled) return;
        setDetail(res.data);
        setChecklist(res.data.investigation_checklist || []);
      } catch (_) {
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const toggleCheck = (id) => {
    setChecklist((prev) => prev.map((c) => (c.id === id ? { ...c, done: !c.done } : c)));
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.55)",
        backdropFilter: "blur(4px)",
        zIndex: 9995,
        display: "flex",
        justifyContent: "flex-end",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 640,
          maxWidth: "100vw",
          height: "100%",
          background: "#11162a",
          borderLeft: "1px solid rgba(100,180,255,0.2)",
          overflowY: "auto",
          padding: 24,
          color: "rgba(255,255,255,0.9)",
        }}
      >
        {loading || !detail ? (
          <div style={{ padding: 30, textAlign: "center", color: "rgba(255,255,255,0.5)" }}>
            Loading incident detail...
          </div>
        ) : (
          <>
            {/* Header */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: 16,
              }}
            >
              <div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", letterSpacing: 2, textTransform: "uppercase" }}>
                  Incident #{detail.incident.id}
                </div>
                <h2 style={{ margin: "4px 0 8px", fontSize: 20, color: "white" }}>
                  {detail.incident.alert_type || "Network Event"}
                </h2>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <Pill color={riskColor(detail.incident.risk_level)} bg={riskBg(detail.incident.risk_level)}>
                    {detail.incident.risk_level || "—"} Risk
                  </Pill>
                  <Pill color="rgba(255,255,255,0.7)">{detail.incident.status || "Pending"}</Pill>
                  {detail.incident.mitre_tactic && (
                    <Pill color="#64b4ff" bg="rgba(100,180,255,0.1)">
                      {detail.incident.mitre_tactic}
                    </Pill>
                  )}
                </div>
              </div>
              <button
                onClick={onClose}
                style={{
                  background: "none",
                  border: "none",
                  color: "rgba(255,255,255,0.5)",
                  fontSize: 24,
                  cursor: "pointer",
                }}
              >
                ×
              </button>
            </div>

            {/* Identity row */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 18 }}>
              <MetaField label="Source" value={detail.incident.source_ip} mono />
              <MetaField label="Destination" value={detail.incident.destination_ip} mono />
              <MetaField label="Domain" value={detail.incident.domain} />
              <MetaField label="Timestamp" value={detail.incident.timestamp} />
            </div>

            {/* Ask AI button */}
            {onAskAI && (
              <button
                onClick={onAskAI}
                style={{
                  width: "100%",
                  padding: "10px 14px",
                  marginBottom: 18,
                  background:
                    "linear-gradient(135deg, rgba(100,180,255,0.2), rgba(170,120,255,0.2))",
                  border: "1px solid rgba(100,180,255,0.4)",
                  borderRadius: 8,
                  color: "white",
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                ✦ Ask AI Companion about this incident
              </button>
            )}

            {/* Evidence */}
            <Section title="AI Evidence">
              <MetaField label="Prediction" value={detail.evidence.ai_prediction} />
              <MetaField label="AI Score" value={detail.evidence.ai_score} />
              <MetaField label="Threat Score" value={detail.evidence.threat_score} />
              <MetaField label="Attack Category" value={detail.evidence.attack_category} />
              <MetaField label="Risk Tier (ABRE)" value={detail.evidence.risk_tier} />
              {detail.evidence.ai_reason && (
                <div
                  style={{
                    marginTop: 8,
                    padding: 12,
                    background: "rgba(100,180,255,0.06)",
                    border: "1px solid rgba(100,180,255,0.2)",
                    borderRadius: 6,
                    fontSize: 12.5,
                    lineHeight: 1.6,
                  }}
                >
                  {detail.evidence.ai_reason}
                </div>
              )}
            </Section>

            {/* Summary */}
            <Section title="Summary">
              <div style={{ fontSize: 13, color: "rgba(255,255,255,0.8)", lineHeight: 1.55 }}>
                {detail.incident.summary || "No summary."}
              </div>
              {detail.incident.recommended_action && (
                <div
                  style={{
                    marginTop: 10,
                    padding: 10,
                    background: "rgba(82,196,26,0.07)",
                    border: "1px solid rgba(82,196,26,0.25)",
                    borderRadius: 6,
                    fontSize: 12.5,
                    color: "rgba(180,255,200,0.9)",
                  }}
                >
                  <strong>Recommended:</strong> {detail.incident.recommended_action}
                </div>
              )}
            </Section>

            {/* Investigation Checklist */}
            <Section title={`Investigation Checklist (${checklist.filter((c) => c.done).length}/${checklist.length})`}>
              {checklist.map((c) => (
                <label
                  key={c.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "8px 4px",
                    fontSize: 13,
                    color: c.done ? "rgba(255,255,255,0.45)" : "rgba(255,255,255,0.85)",
                    textDecoration: c.done ? "line-through" : "none",
                    cursor: "pointer",
                  }}
                >
                  <input type="checkbox" checked={c.done} onChange={() => toggleCheck(c.id)} />
                  {c.label}
                </label>
              ))}
            </Section>

            {/* Related incidents */}
            <Section title={`Related Incidents (${detail.related_incidents.length})`}>
              {detail.related_incidents.length === 0 ? (
                <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>
                  No correlated incidents found.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {detail.related_incidents.slice(0, 10).map((r) => (
                    <div
                      key={r.id}
                      style={{
                        padding: "8px 10px",
                        background: "rgba(255,255,255,0.03)",
                        border: "1px solid rgba(255,255,255,0.06)",
                        borderRadius: 6,
                        fontSize: 12.5,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                        <span style={{ fontWeight: 600, color: "white" }}>
                          #{r.id} · {r.alert_type || "Event"}
                        </span>
                        <Pill color={riskColor(r.risk_level)} bg={riskBg(r.risk_level)}>
                          {r.risk_level || "—"}
                        </Pill>
                      </div>
                      <div
                        style={{
                          fontSize: 11,
                          color: "rgba(255,255,255,0.55)",
                          fontFamily: "ui-monospace, monospace",
                        }}
                      >
                        {r.source_ip || "?"} → {r.destination_ip || "?"}
                        {r.mitre_tactic && ` · ${r.mitre_tactic}`}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Section>

            {/* Timeline */}
            <Section title="Activity Timeline">
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {detail.timeline.map((e) => (
                  <div
                    key={e.incident_id}
                    style={{
                      display: "flex",
                      gap: 10,
                      padding: "6px 0",
                      borderBottom: "1px solid rgba(255,255,255,0.04)",
                      fontSize: 12,
                    }}
                  >
                    <div
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: "50%",
                        background: riskColor(e.risk_level),
                        marginTop: 5,
                        flexShrink: 0,
                        boxShadow: `0 0 8px ${riskColor(e.risk_level)}`,
                      }}
                    />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: "white" }}>
                        #{e.incident_id} {e.alert_type}
                      </div>
                      <div
                        style={{
                          fontSize: 11,
                          color: "rgba(255,255,255,0.5)",
                          fontFamily: "ui-monospace, monospace",
                        }}
                      >
                        {e.timestamp || "—"} · {e.source_ip || "?"} → {e.destination_ip || "?"}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div
        style={{
          fontSize: 11,
          color: "rgba(255,255,255,0.4)",
          letterSpacing: 1.5,
          textTransform: "uppercase",
          marginBottom: 8,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function MetaField({ label, value, mono = false }) {
  return (
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: 6,
        padding: "8px 10px",
      }}
    >
      <div style={{ fontSize: 10, color: "rgba(255,255,255,0.45)", textTransform: "uppercase", letterSpacing: 1 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 13,
          color: "rgba(255,255,255,0.9)",
          fontFamily: mono ? "ui-monospace, monospace" : "inherit",
          marginTop: 2,
          wordBreak: "break-all",
        }}
      >
        {value === null || value === undefined || value === "" ? "—" : String(value)}
      </div>
    </div>
  );
}
