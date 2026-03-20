import { useQuery } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";

const RISK_COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
};

const STATUS_COLORS = {
  Pending: "#eab308",
  Approved: "#22c55e",
  Rejected: "#ef4444",
  Resolved: "#10b981",
  Escalated: "#a855f7",
};

export default function AnalyticsPage() {
  const { data: analytics, isLoading } = useQuery({
    queryKey: ["analytics"],
    queryFn: () => incidentsApi.analytics().then((r) => r.data),
    refetchInterval: 60_000,
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4 animate-pulse">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-48 bg-slate-800 rounded-xl" />
        ))}
      </div>
    );
  }

  if (!analytics) return null;

  const riskData = [
    { name: "Critical", value: analytics.critical },
    { name: "High", value: analytics.high },
    { name: "Medium", value: analytics.medium },
    { name: "Low", value: analytics.low },
  ].filter((d) => d.value > 0);

  const statusData = [
    { name: "Pending", value: analytics.pending },
    { name: "Approved", value: analytics.approved },
    { name: "Rejected", value: analytics.rejected },
    { name: "Resolved", value: analytics.resolved },
    { name: "Escalated", value: 0 },
  ].filter((d) => d.value > 0);

  const overviewData = [
    { name: "Total", value: analytics.total_incidents },
    { name: "AI Anomalies", value: analytics.ai_detected_anomalies },
    { name: "False Positives", value: analytics.false_positives },
    { name: "Pending", value: analytics.pending },
  ];

  const accuracy =
    analytics.total_incidents > 0
      ? Math.round(
          ((analytics.total_incidents - analytics.false_positives) / analytics.total_incidents) * 100
        )
      : 0;

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Analytics</h1>
        <p className="text-slate-400 text-sm mt-0.5">Threat detection performance and incident trends</p>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Incidents", value: analytics.total_incidents, color: "text-blue-400" },
          { label: "AI Detection Rate", value: `${analytics.ai_detected_anomalies}`, sub: "anomalies", color: "text-purple-400" },
          { label: "Model Accuracy", value: `${accuracy}%`, color: accuracy > 80 ? "text-green-400" : "text-yellow-400" },
          { label: "False Positive Rate", value: analytics.false_positives, color: "text-orange-400" },
        ].map(({ label, value, color, sub }) => (
          <div key={label} className="card">
            <p className={`text-3xl font-bold ${color}`}>{value}</p>
            {sub && <p className="text-xs text-slate-600">{sub}</p>}
            <p className="text-sm text-slate-400 mt-1">{label}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Pie */}
        <div className="card">
          <h2 className="font-semibold text-slate-200 mb-4">Risk Level Distribution</h2>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={70}
                  outerRadius={100}
                  paddingAngle={3}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name as keyof typeof RISK_COLORS]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                  labelStyle={{ color: "#f1f5f9" }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-center text-slate-500 py-20">No data yet</p>
          )}
        </div>

        {/* Status Distribution */}
        <div className="card">
          <h2 className="font-semibold text-slate-200 mb-4">Status Distribution</h2>
          {statusData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={statusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={70}
                  outerRadius={100}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {statusData.map((entry) => (
                    <Cell key={entry.name} fill={STATUS_COLORS[entry.name as keyof typeof STATUS_COLORS] ?? "#64748b"} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-center text-slate-500 py-20">No data yet</p>
          )}
        </div>

        {/* Overview Bar Chart */}
        <div className="card lg:col-span-2">
          <h2 className="font-semibold text-slate-200 mb-4">Platform Overview</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={overviewData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 12 }} />
              <YAxis tick={{ fill: "#94a3b8", fontSize: 12 }} />
              <Tooltip
                contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                labelStyle={{ color: "#f1f5f9" }}
              />
              <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
