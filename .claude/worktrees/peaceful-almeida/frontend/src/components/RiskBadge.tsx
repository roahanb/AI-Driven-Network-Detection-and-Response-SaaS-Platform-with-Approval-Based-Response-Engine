import type { RiskLevel, IncidentStatus } from "@/types";

const RISK_STYLES: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-400 border border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
  Low: "bg-green-500/20 text-green-400 border border-green-500/30",
  Info: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
};

const STATUS_STYLES: Record<string, string> = {
  Pending: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
  Approved: "bg-green-500/20 text-green-400 border border-green-500/30",
  Rejected: "bg-red-500/20 text-red-400 border border-red-500/30",
  "In Progress": "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  Resolved: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
  Escalated: "bg-purple-500/20 text-purple-400 border border-purple-500/30",
};

export function RiskBadge({ level }: { level: RiskLevel | string | null }) {
  if (!level) return null;
  const cls = RISK_STYLES[level] ?? "bg-slate-700 text-slate-300";
  return (
    <span className={`badge ${cls}`}>
      {level === "Critical" && "🔴 "}
      {level === "High" && "🟠 "}
      {level === "Medium" && "🟡 "}
      {level === "Low" && "🟢 "}
      {level}
    </span>
  );
}

export function StatusBadge({ status }: { status: IncidentStatus | string | null }) {
  if (!status) return null;
  const cls = STATUS_STYLES[status] ?? "bg-slate-700 text-slate-300";
  return <span className={`badge ${cls}`}>{status}</span>;
}

export function AIPredictionBadge({ prediction }: { prediction: string | null }) {
  if (!prediction) return null;
  const isSuspicious = prediction === "suspicious";
  return (
    <span
      className={`badge ${
        isSuspicious
          ? "bg-red-500/20 text-red-400 border border-red-500/30"
          : "bg-slate-700/50 text-slate-400 border border-slate-700"
      }`}
    >
      {isSuspicious ? "⚠ Suspicious" : "✓ Normal"}
    </span>
  );
}
