import { useQuery } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import { useAuthStore } from "@/store/authStore";
import { AlertTriangle, CheckCircle, XCircle, Clock, TrendingUp, Shield, Activity } from "lucide-react";
import { RiskBadge, StatusBadge, AIPredictionBadge } from "@/components/RiskBadge";
import LogUploader from "@/components/LogUploader";
import { formatDistanceToNow } from "date-fns";
import { Link } from "react-router-dom";

function MetricCard({
  label, value, icon: Icon, color, sub,
}: {
  label: string; value: number | string; icon: React.ElementType; color: string; sub?: string;
}) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${color}`}>
        <Icon size={22} className="text-white" />
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-sm text-slate-400">{label}</p>
        {sub && <p className="text-xs text-slate-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const user = useAuthStore((s) => s.user);

  const { data: analytics } = useQuery({
    queryKey: ["analytics"],
    queryFn: () => incidentsApi.analytics().then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: recent } = useQuery({
    queryKey: ["incidents", "recent"],
    queryFn: () => incidentsApi.list({ page: 1, page_size: 8 }).then((r) => r.data),
    refetchInterval: 15_000,
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">
          Welcome back, {user?.full_name?.split(" ")[0]}
        </h1>
        <p className="text-slate-400 text-sm mt-0.5">
          Security operations dashboard · Real-time threat monitoring
        </p>
      </div>

      {/* Metric Cards */}
      {analytics && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            label="Total Incidents"
            value={analytics.total_incidents}
            icon={Shield}
            color="bg-blue-600"
          />
          <MetricCard
            label="Pending Review"
            value={analytics.pending}
            icon={Clock}
            color="bg-yellow-600"
            sub="Awaiting approval"
          />
          <MetricCard
            label="AI Anomalies"
            value={analytics.ai_detected_anomalies}
            icon={Activity}
            color="bg-purple-600"
            sub="ML-detected threats"
          />
          <MetricCard
            label="Critical / High"
            value={`${analytics.critical} / ${analytics.high}`}
            icon={AlertTriangle}
            color="bg-red-600"
            sub="Needs immediate attention"
          />
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Log Uploader */}
        <div className="xl:col-span-1 space-y-4">
          <h2 className="font-semibold text-slate-200">Upload Logs</h2>
          <LogUploader />

          {/* Status breakdown */}
          {analytics && (
            <div className="card space-y-3">
              <h3 className="text-sm font-semibold text-slate-300">Status Breakdown</h3>
              {[
                { label: "Pending", value: analytics.pending, color: "bg-yellow-500" },
                { label: "Approved", value: analytics.approved, color: "bg-green-500" },
                { label: "Rejected", value: analytics.rejected, color: "bg-red-500" },
                { label: "Resolved", value: analytics.resolved, color: "bg-emerald-500" },
              ].map(({ label, value, color }) => {
                const pct = analytics.total_incidents
                  ? Math.round((value / analytics.total_incidents) * 100)
                  : 0;
                return (
                  <div key={label}>
                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                      <span>{label}</span>
                      <span>{value} ({pct}%)</span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full">
                      <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Risk breakdown */}
          {analytics && (
            <div className="card space-y-2">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Risk Distribution</h3>
              {[
                { label: "Critical", value: analytics.critical, color: "text-red-400" },
                { label: "High", value: analytics.high, color: "text-orange-400" },
                { label: "Medium", value: analytics.medium, color: "text-yellow-400" },
                { label: "Low", value: analytics.low, color: "text-green-400" },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex justify-between items-center">
                  <span className={`text-sm font-medium ${color}`}>{label}</span>
                  <span className="text-sm text-slate-300">{value}</span>
                </div>
              ))}
              {analytics.false_positives > 0 && (
                <div className="pt-2 border-t border-slate-800 flex justify-between items-center">
                  <span className="text-sm text-slate-500">False Positives</span>
                  <span className="text-sm text-slate-500">{analytics.false_positives}</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Recent Incidents */}
        <div className="xl:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-slate-200">Recent Incidents</h2>
            <Link to="/incidents" className="text-sm text-blue-400 hover:text-blue-300">
              View all →
            </Link>
          </div>

          <div className="space-y-2">
            {recent?.items.map((incident) => (
              <Link
                key={incident.id}
                to={`/incidents/${incident.id}`}
                className="card hover:border-slate-700 transition-colors block"
              >
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-slate-200">
                        #{incident.id} · {incident.alert_type || "Unknown Alert"}
                      </span>
                      <RiskBadge level={incident.risk_level} />
                      <StatusBadge status={incident.status} />
                      {incident.ai_prediction === "suspicious" && (
                        <AIPredictionBadge prediction={incident.ai_prediction} />
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      {incident.source_ip} → {incident.destination_ip}
                      {incident.domain && ` · ${incident.domain}`}
                    </p>
                    <p className="text-xs text-slate-600 mt-0.5">
                      {incident.created_at && formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}
                    </p>
                  </div>
                  <span className="text-slate-600 text-sm flex-shrink-0">→</span>
                </div>
              </Link>
            ))}

            {recent?.items.length === 0 && (
              <div className="card text-center py-10">
                <Shield className="w-10 h-10 mx-auto text-slate-700 mb-3" />
                <p className="text-slate-400">No incidents yet</p>
                <p className="text-sm text-slate-600 mt-1">Upload log files to start detection</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
