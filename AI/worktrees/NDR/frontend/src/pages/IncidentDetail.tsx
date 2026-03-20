import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import { RiskBadge, StatusBadge, AIPredictionBadge } from "@/components/RiskBadge";
import ApprovalModal from "@/components/ApprovalModal";
import { useState } from "react";
import { ArrowLeft, CheckCircle, XCircle, AlertTriangle, Brain, Network, Clock, Shield } from "lucide-react";
import { format } from "date-fns";
import { useAuthStore } from "@/store/authStore";
import type { Incident } from "@/types";

type ModalAction = "approve" | "reject" | "escalate";

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">{label}</dt>
      <dd className="text-sm text-slate-200">{value || "—"}</dd>
    </div>
  );
}

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const canAct = user?.role === "admin" || user?.role === "analyst";
  const [modal, setModal] = useState<{ incident: Incident; action: ModalAction } | null>(null);

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => incidentsApi.get(Number(id)).then((r) => r.data),
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4 animate-pulse">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-16 bg-slate-800 rounded-xl" />
        ))}
      </div>
    );
  }

  if (!incident) return <div className="p-6 text-slate-400">Incident not found</div>;

  const score = incident.confidence_score;
  const scoreColor = score && score > 0.7 ? "text-red-400" : score && score > 0.4 ? "text-yellow-400" : "text-green-400";

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Back + Header */}
      <div>
        <button
          onClick={() => navigate(-1)}
          className="flex items-center gap-2 text-slate-400 hover:text-slate-200 text-sm mb-4"
        >
          <ArrowLeft size={16} /> Back to incidents
        </button>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-2xl font-bold text-white">Incident #{incident.id}</h1>
            <p className="text-slate-400 text-sm mt-0.5">{incident.alert_type}</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <RiskBadge level={incident.risk_level} />
            <StatusBadge status={incident.status} />
            <AIPredictionBadge prediction={incident.ai_prediction} />
          </div>
        </div>
      </div>

      {/* Action buttons */}
      {canAct && incident.status === "Pending" && (
        <div className="flex gap-3 flex-wrap">
          <button
            onClick={() => setModal({ incident, action: "approve" })}
            className="btn-primary flex items-center gap-2"
          >
            <CheckCircle size={16} /> Approve Response
          </button>
          <button
            onClick={() => setModal({ incident, action: "reject" })}
            className="btn-danger flex items-center gap-2"
          >
            <XCircle size={16} /> Reject
          </button>
          <button
            onClick={() => setModal({ incident, action: "escalate" })}
            className="bg-purple-600 hover:bg-purple-700 text-white font-medium px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
          >
            <AlertTriangle size={16} /> Escalate
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Network Details */}
        <div className="card space-y-4">
          <h2 className="font-semibold text-slate-200 flex items-center gap-2">
            <Network size={16} className="text-blue-400" /> Network Details
          </h2>
          <dl className="grid grid-cols-2 gap-4">
            <Field label="Source IP" value={<span className="font-mono">{incident.source_ip}</span>} />
            <Field label="Destination IP" value={<span className="font-mono">{incident.destination_ip}</span>} />
            <Field label="Domain" value={incident.domain} />
            <Field label="Alert Type" value={incident.alert_type} />
            <Field label="Log Timestamp" value={incident.timestamp} />
            <Field label="Log Source" value={incident.log_source} />
          </dl>
        </div>

        {/* AI Analysis */}
        <div className="card space-y-4">
          <h2 className="font-semibold text-slate-200 flex items-center gap-2">
            <Brain size={16} className="text-purple-400" /> AI Analysis
          </h2>
          <dl className="grid grid-cols-2 gap-4">
            <Field
              label="Prediction"
              value={<AIPredictionBadge prediction={incident.ai_prediction} />}
            />
            <Field
              label="Confidence"
              value={
                score !== null && score !== undefined ? (
                  <span className={`font-semibold ${scoreColor}`}>
                    {Math.round(score * 100)}%
                  </span>
                ) : "—"
              }
            />
            <Field
              label="Anomaly Score"
              value={incident.ai_score !== null ? incident.ai_score?.toFixed(4) : "—"}
            />
          </dl>
          {incident.ai_reason && (
            <div>
              <dt className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">AI Reasoning</dt>
              <dd className="text-sm text-slate-300 bg-slate-800 rounded-lg p-3 leading-relaxed">
                {incident.ai_reason}
              </dd>
            </div>
          )}
        </div>

        {/* Summary & Action */}
        <div className="card md:col-span-2 space-y-4">
          <h2 className="font-semibold text-slate-200">Summary & Recommended Action</h2>
          <div>
            <dt className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Summary</dt>
            <dd className="text-sm text-slate-300 leading-relaxed">{incident.summary || "—"}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Recommended Action</dt>
            <dd className="text-sm font-medium text-yellow-400">{incident.recommended_action || "—"}</dd>
          </div>
        </div>

        {/* MITRE ATT&CK */}
        {(incident.mitre_tactic || incident.mitre_technique) && (
          <div className="card md:col-span-2 space-y-3">
            <h2 className="font-semibold text-slate-200 flex items-center gap-2">
              <Shield size={16} className="text-orange-400" /> MITRE ATT&amp;CK Framework
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <dt className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Tactic</dt>
                <dd className="text-sm text-slate-200">{incident.mitre_tactic || "—"}</dd>
                {incident.mitre_tactic_id && (
                  <span className="text-xs font-mono text-orange-400">{incident.mitre_tactic_id}</span>
                )}
              </div>
              <div className="md:col-span-3">
                <dt className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Technique</dt>
                <dd className="text-sm text-slate-200">{incident.mitre_technique || "—"}</dd>
                {incident.mitre_technique_id && (
                  <a
                    href={`https://attack.mitre.org/techniques/${incident.mitre_technique_id.replace(".", "/")}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-orange-400 hover:text-orange-300 underline"
                  >
                    {incident.mitre_technique_id} ↗
                  </a>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Approval Info */}
        {incident.approved_by_id && (
          <div className="card md:col-span-2 space-y-4">
            <h2 className="font-semibold text-slate-200 flex items-center gap-2">
              <Clock size={16} className="text-slate-400" /> Decision History
            </h2>
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Field label="Decision" value={<StatusBadge status={incident.status} />} />
              <Field
                label="Decided At"
                value={incident.approved_at ? format(new Date(incident.approved_at), "MMM d, yyyy HH:mm") : "—"}
              />
              <Field label="Comment" value={incident.approval_comment} />
              <Field label="Action Taken" value={incident.action_taken} />
            </dl>
            {incident.is_false_positive && (
              <div className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-slate-700 text-xs text-slate-400">
                Marked as False Positive
              </div>
            )}
          </div>
        )}
      </div>

      {modal && (
        <ApprovalModal
          incident={modal.incident}
          action={modal.action}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  );
}
