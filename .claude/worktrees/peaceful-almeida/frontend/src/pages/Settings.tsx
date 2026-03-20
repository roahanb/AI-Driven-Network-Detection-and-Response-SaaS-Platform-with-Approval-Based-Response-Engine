import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { authApi } from "@/api/auth";
import { useAuthStore } from "@/store/authStore";
import { User, Bell, Lock, Building } from "lucide-react";
import toast from "react-hot-toast";

export default function SettingsPage() {
  const { user } = useAuthStore();
  const [passwords, setPasswords] = useState({ current: "", new: "", confirm: "" });

  const pwMutation = useMutation({
    mutationFn: () => authApi.changePassword(passwords.current, passwords.new),
    onSuccess: () => {
      toast.success("Password updated");
      setPasswords({ current: "", new: "", confirm: "" });
    },
    onError: (err: { response?: { data?: { detail?: string } } }) => {
      toast.error(err?.response?.data?.detail ?? "Failed to update password");
    },
  });

  const handlePwSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (passwords.new !== passwords.confirm) {
      toast.error("New passwords do not match");
      return;
    }
    if (passwords.new.length < 8) {
      toast.error("Password must be at least 8 characters");
      return;
    }
    pwMutation.mutate();
  };

  return (
    <div className="p-6 space-y-6 max-w-2xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 text-sm mt-0.5">Manage your account and preferences</p>
      </div>

      {/* Profile */}
      <div className="card space-y-4">
        <h2 className="font-semibold text-slate-200 flex items-center gap-2">
          <User size={16} className="text-blue-400" /> Profile
        </h2>
        <dl className="grid grid-cols-2 gap-4">
          {[
            { label: "Full Name", value: user?.full_name },
            { label: "Email", value: user?.email },
            { label: "Role", value: <span className="capitalize">{user?.role}</span> },
            { label: "Account Status", value: user?.is_active ? "Active" : "Inactive" },
          ].map(({ label, value }) => (
            <div key={label}>
              <dt className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</dt>
              <dd className="text-sm text-slate-200">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Organization */}
      <div className="card space-y-3">
        <h2 className="font-semibold text-slate-200 flex items-center gap-2">
          <Building size={16} className="text-green-400" /> Organization
        </h2>
        <p className="text-sm text-slate-400">Organization ID: <span className="text-slate-200 font-mono">{user?.organization_id}</span></p>
        <p className="text-xs text-slate-600">Contact your admin to update organization settings like Slack webhook and notification preferences.</p>
      </div>

      {/* Notifications */}
      <div className="card space-y-3">
        <h2 className="font-semibold text-slate-200 flex items-center gap-2">
          <Bell size={16} className="text-yellow-400" /> Notifications
        </h2>
        <div className="space-y-2 text-sm text-slate-400">
          <p>Email notifications: <span className={user?.notification_email ? "text-green-400" : "text-slate-600"}>{user?.notification_email ? "Enabled" : "Disabled"}</span></p>
          <p>Slack notifications: <span className={user?.notification_slack ? "text-green-400" : "text-slate-600"}>{user?.notification_slack ? "Enabled" : "Disabled"}</span></p>
          <p className="text-xs text-slate-600 pt-1">Ask your admin to update your notification preferences.</p>
        </div>
      </div>

      {/* Change Password */}
      <form onSubmit={handlePwSubmit} className="card space-y-4">
        <h2 className="font-semibold text-slate-200 flex items-center gap-2">
          <Lock size={16} className="text-purple-400" /> Change Password
        </h2>
        {[
          { key: "current", label: "Current Password", placeholder: "••••••••" },
          { key: "new", label: "New Password", placeholder: "Min 8 characters" },
          { key: "confirm", label: "Confirm New Password", placeholder: "••••••••" },
        ].map(({ key, label, placeholder }) => (
          <div key={key}>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">{label}</label>
            <input
              type="password"
              className="input"
              placeholder={placeholder}
              value={passwords[key as keyof typeof passwords]}
              onChange={(e) => setPasswords((p) => ({ ...p, [key]: e.target.value }))}
              required
            />
          </div>
        ))}
        <button type="submit" className="btn-primary" disabled={pwMutation.isPending}>
          {pwMutation.isPending ? "Updating..." : "Update Password"}
        </button>
      </form>
    </div>
  );
}
