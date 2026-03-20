import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/store/authStore";
import { UserPlus, Shield, Eye, Edit } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { format } from "date-fns";
import type { User } from "@/types";

const ROLE_BADGE: Record<string, string> = {
  admin: "bg-purple-500/20 text-purple-400 border border-purple-500/30",
  analyst: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  viewer: "bg-slate-700/50 text-slate-400 border border-slate-700",
};

const ROLE_ICON: Record<string, React.ElementType> = {
  admin: Shield,
  analyst: Edit,
  viewer: Eye,
};

export default function UsersPage() {
  const currentUser = useAuthStore((s) => s.user);
  const isAdmin = currentUser?.role === "admin";
  const qc = useQueryClient();

  const [inviteForm, setInviteForm] = useState({ email: "", full_name: "", role: "analyst" });
  const [showInvite, setShowInvite] = useState(false);

  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ["users"],
    queryFn: () => apiClient.get<User[]>("/users").then((r) => r.data),
    enabled: isAdmin,
  });

  const inviteMutation = useMutation({
    mutationFn: () => apiClient.post("/users/invite", inviteForm),
    onSuccess: () => {
      toast.success(`Invited ${inviteForm.email}`);
      qc.invalidateQueries({ queryKey: ["users"] });
      setShowInvite(false);
      setInviteForm({ email: "", full_name: "", role: "analyst" });
    },
    onError: (err: { response?: { data?: { detail?: string } } }) => {
      toast.error(err?.response?.data?.detail ?? "Invite failed");
    },
  });

  const roleChangeMutation = useMutation({
    mutationFn: ({ userId, role }: { userId: number; role: string }) =>
      apiClient.patch(`/users/${userId}/role`, { role }),
    onSuccess: () => {
      toast.success("Role updated");
      qc.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: (userId: number) => apiClient.delete(`/users/${userId}`),
    onSuccess: () => {
      toast.success("User deactivated");
      qc.invalidateQueries({ queryKey: ["users"] });
    },
  });

  if (!isAdmin) {
    return (
      <div className="p-6">
        <div className="card text-center py-12">
          <Shield className="w-10 h-10 mx-auto text-slate-700 mb-3" />
          <p className="text-slate-400">Admin access required to manage users</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-5 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Team Members</h1>
          <p className="text-slate-400 text-sm mt-0.5">{users.length} users in your organization</p>
        </div>
        <button onClick={() => setShowInvite(true)} className="btn-primary flex items-center gap-2">
          <UserPlus size={16} /> Invite User
        </button>
      </div>

      {/* Invite form */}
      {showInvite && (
        <div className="card space-y-4">
          <h3 className="font-semibold text-slate-200">Invite Team Member</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              className="input"
              placeholder="Email address"
              type="email"
              value={inviteForm.email}
              onChange={(e) => setInviteForm((f) => ({ ...f, email: e.target.value }))}
            />
            <input
              className="input"
              placeholder="Full name"
              value={inviteForm.full_name}
              onChange={(e) => setInviteForm((f) => ({ ...f, full_name: e.target.value }))}
            />
            <select
              className="input"
              value={inviteForm.role}
              onChange={(e) => setInviteForm((f) => ({ ...f, role: e.target.value }))}
            >
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="flex gap-3">
            <button className="btn-primary" onClick={() => inviteMutation.mutate()} disabled={inviteMutation.isPending}>
              {inviteMutation.isPending ? "Inviting..." : "Send Invite"}
            </button>
            <button className="btn-secondary" onClick={() => setShowInvite(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Users table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
              {["Member", "Role", "Status", "Last Login", "Notifications", "Actions"].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {isLoading
              ? Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-4 bg-slate-800 rounded animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              : users.map((u) => {
                  const RoleIcon = ROLE_ICON[u.role] ?? Eye;
                  return (
                    <tr key={u.id} className="hover:bg-slate-800/40">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-blue-700 flex items-center justify-center text-xs font-bold">
                            {u.full_name[0]?.toUpperCase()}
                          </div>
                          <div>
                            <p className="font-medium text-slate-200">{u.full_name}</p>
                            <p className="text-xs text-slate-500">{u.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`badge ${ROLE_BADGE[u.role]}`}>
                          <RoleIcon size={11} /> {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`badge ${u.is_active ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
                          {u.is_active ? "Active" : "Inactive"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {u.last_login ? format(new Date(u.last_login), "MMM d, HH:mm") : "Never"}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {[u.notification_email && "Email", u.notification_slack && "Slack"]
                          .filter(Boolean)
                          .join(", ") || "None"}
                      </td>
                      <td className="px-4 py-3">
                        {currentUser?.id !== u.id && (
                          <div className="flex gap-2">
                            <select
                              className="input text-xs py-1 w-auto"
                              value={u.role}
                              onChange={(e) => roleChangeMutation.mutate({ userId: u.id, role: e.target.value })}
                            >
                              <option value="analyst">Analyst</option>
                              <option value="viewer">Viewer</option>
                              <option value="admin">Admin</option>
                            </select>
                            {u.is_active && (
                              <button
                                onClick={() => deactivateMutation.mutate(u.id)}
                                className="text-xs text-red-400 hover:text-red-300 px-2 py-1 rounded-lg hover:bg-red-400/10 transition-colors"
                              >
                                Deactivate
                              </button>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
