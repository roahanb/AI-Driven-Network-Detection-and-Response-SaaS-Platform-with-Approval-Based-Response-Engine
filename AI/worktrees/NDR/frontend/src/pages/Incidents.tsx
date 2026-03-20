import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import { RiskBadge, StatusBadge, AIPredictionBadge } from "@/components/RiskBadge";
import ApprovalModal from "@/components/ApprovalModal";
import { Filter, Search, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Link } from "react-router-dom";
import type { Incident } from "@/types";
import { useAuthStore } from "@/store/authStore";

type ModalAction = "approve" | "reject" | "escalate";

export default function IncidentsPage() {
  const user = useAuthStore((s) => s.user);
  const canAct = user?.role === "admin" || user?.role === "analyst";

  const [filters, setFilters] = useState({
    status: "",
    risk_level: "",
    ai_prediction: "",
    source_ip: "",
    page: 1,
    page_size: 20,
  });
  const [modal, setModal] = useState<{ incident: Incident; action: ModalAction } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["incidents", filters],
    queryFn: () =>
      incidentsApi
        .list({
          ...filters,
          status: filters.status || undefined,
          risk_level: filters.risk_level || undefined,
          ai_prediction: filters.ai_prediction || undefined,
          source_ip: filters.source_ip || undefined,
        })
        .then((r) => r.data),
    refetchInterval: 20_000,
  });

  const setFilter = (k: string, v: string) =>
    setFilters((f) => ({ ...f, [k]: v, page: 1 }));

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Incidents</h1>
          <p className="text-slate-400 text-sm mt-0.5">
            {data?.total ?? 0} total incidents
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="card flex flex-wrap gap-3 items-center">
        <Filter size={16} className="text-slate-500" />

        <select
          className="input w-auto text-sm"
          value={filters.status}
          onChange={(e) => setFilter("status", e.target.value)}
        >
          <option value="">All Status</option>
          {["Pending", "Approved", "Rejected", "In Progress", "Resolved", "Escalated"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <select
          className="input w-auto text-sm"
          value={filters.risk_level}
          onChange={(e) => setFilter("risk_level", e.target.value)}
        >
          <option value="">All Risk Levels</option>
          {["Critical", "High", "Medium", "Low"].map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>

        <select
          className="input w-auto text-sm"
          value={filters.ai_prediction}
          onChange={(e) => setFilter("ai_prediction", e.target.value)}
        >
          <option value="">All AI Predictions</option>
          <option value="suspicious">Suspicious</option>
          <option value="normal">Normal</option>
        </select>

        <div className="relative flex-1 min-w-[180px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            className="input pl-8 text-sm"
            placeholder="Filter by source IP..."
            value={filters.source_ip}
            onChange={(e) => setFilter("source_ip", e.target.value)}
          />
        </div>

        {(filters.status || filters.risk_level || filters.ai_prediction || filters.source_ip) && (
          <button
            className="text-sm text-slate-400 hover:text-slate-200"
            onClick={() => setFilters({ status: "", risk_level: "", ai_prediction: "", source_ip: "", page: 1, page_size: 20 })}
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                {["ID", "Alert Type", "Source IP", "Destination", "Risk", "Status", "AI", "Time", "Actions"].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 9 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-4 bg-slate-800 rounded animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : data?.items.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-10 text-center text-slate-500">
                    No incidents found matching your filters
                  </td>
                </tr>
              ) : (
                data?.items.map((incident) => (
                  <tr key={incident.id} className="hover:bg-slate-800/50 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-400">#{incident.id}</td>
                    <td className="px-4 py-3">
                      <Link to={`/incidents/${incident.id}`} className="text-slate-200 hover:text-blue-400 font-medium truncate max-w-[180px] block">
                        {incident.alert_type || "—"}
                      </Link>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400 text-xs">{incident.source_ip}</td>
                    <td className="px-4 py-3 font-mono text-slate-400 text-xs">{incident.destination_ip}</td>
                    <td className="px-4 py-3"><RiskBadge level={incident.risk_level} /></td>
                    <td className="px-4 py-3"><StatusBadge status={incident.status} /></td>
                    <td className="px-4 py-3"><AIPredictionBadge prediction={incident.ai_prediction} /></td>
                    <td className="px-4 py-3 text-xs text-slate-500">
                      {incident.created_at && formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3">
                      {canAct && incident.status === "Pending" && (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setModal({ incident, action: "approve" })}
                            className="p-1.5 text-green-400 hover:bg-green-400/10 rounded-lg transition-colors"
                            title="Approve"
                          >
                            <CheckCircle size={15} />
                          </button>
                          <button
                            onClick={() => setModal({ incident, action: "reject" })}
                            className="p-1.5 text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                            title="Reject"
                          >
                            <XCircle size={15} />
                          </button>
                          <button
                            onClick={() => setModal({ incident, action: "escalate" })}
                            className="p-1.5 text-purple-400 hover:bg-purple-400/10 rounded-lg transition-colors"
                            title="Escalate"
                          >
                            <AlertTriangle size={15} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800">
            <p className="text-sm text-slate-500">
              Page {data.page} of {data.pages} · {data.total} incidents
            </p>
            <div className="flex gap-2">
              <button
                className="btn-secondary text-xs px-3 py-1.5"
                disabled={data.page <= 1}
                onClick={() => setFilters((f) => ({ ...f, page: f.page - 1 }))}
              >
                Previous
              </button>
              <button
                className="btn-secondary text-xs px-3 py-1.5"
                disabled={data.page >= data.pages}
                onClick={() => setFilters((f) => ({ ...f, page: f.page + 1 }))}
              >
                Next
              </button>
            </div>
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
