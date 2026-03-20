import { useState } from "react";
import { X, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import toast from "react-hot-toast";
import type { Incident } from "@/types";

interface Props {
  incident: Incident;
  action: "approve" | "reject" | "escalate";
  onClose: () => void;
}

export default function ApprovalModal({ incident, action, onClose }: Props) {
  const [comment, setComment] = useState("");
  const [actionTaken, setActionTaken] = useState("");
  const [isFalsePositive, setIsFalsePositive] = useState(false);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => {
      if (action === "approve") return incidentsApi.approve(incident.id, { comment, action_taken: actionTaken });
      if (action === "reject") return incidentsApi.reject(incident.id, { comment, is_false_positive: isFalsePositive });
      return incidentsApi.escalate(incident.id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
      toast.success(`Incident #${incident.id} ${action}d successfully`);
      onClose();
    },
    onError: (err: Error) => {
      toast.error(`Failed: ${err.message}`);
    },
  });

  const config = {
    approve: {
      title: "Approve Incident",
      icon: CheckCircle,
      iconColor: "text-green-400",
      btnClass: "bg-green-600 hover:bg-green-700 text-white",
      btnLabel: "Approve & Execute",
    },
    reject: {
      title: "Reject Incident",
      icon: XCircle,
      iconColor: "text-red-400",
      btnClass: "bg-red-600 hover:bg-red-700 text-white",
      btnLabel: "Reject Incident",
    },
    escalate: {
      title: "Escalate Incident",
      icon: AlertTriangle,
      iconColor: "text-purple-400",
      btnClass: "bg-purple-600 hover:bg-purple-700 text-white",
      btnLabel: "Escalate",
    },
  }[action];

  const Icon = config.icon;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-md mx-4 shadow-2xl animate-slide-in">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <Icon size={20} className={config.iconColor} />
            <h2 className="font-semibold text-white">{config.title}</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4">
          {/* Incident summary */}
          <div className="bg-slate-800 rounded-lg p-3 text-sm space-y-1">
            <p className="text-slate-400">
              <span className="text-slate-300 font-medium">Incident #</span>{incident.id}
            </p>
            <p className="text-slate-400">
              <span className="text-slate-300 font-medium">Type: </span>{incident.alert_type}
            </p>
            <p className="text-slate-400">
              <span className="text-slate-300 font-medium">Source IP: </span>{incident.source_ip}
            </p>
          </div>

          {/* Action taken (approve only) */}
          {action === "approve" && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Action Taken <span className="text-slate-500">(optional)</span>
              </label>
              <input
                className="input"
                placeholder="e.g. Blocked IP at firewall, isolated host..."
                value={actionTaken}
                onChange={(e) => setActionTaken(e.target.value)}
              />
            </div>
          )}

          {/* False positive checkbox (reject only) */}
          {action === "reject" && (
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={isFalsePositive}
                onChange={(e) => setIsFalsePositive(e.target.checked)}
                className="w-4 h-4 accent-blue-500"
              />
              <span className="text-sm text-slate-300">Mark as false positive</span>
            </label>
          )}

          {/* Comment */}
          {action !== "escalate" && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Comment <span className="text-slate-500">(optional)</span>
              </label>
              <textarea
                className="input resize-none"
                rows={3}
                placeholder="Add a comment for the audit trail..."
                value={comment}
                onChange={(e) => setComment(e.target.value)}
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-3 p-5 border-t border-slate-800">
          <button onClick={onClose} className="btn-secondary flex-1">
            Cancel
          </button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className={`flex-1 font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50 ${config.btnClass}`}
          >
            {mutation.isPending ? "Processing..." : config.btnLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
