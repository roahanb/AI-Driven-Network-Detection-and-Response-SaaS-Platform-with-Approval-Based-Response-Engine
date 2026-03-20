import { Outlet, NavLink, useNavigate } from "react-router-dom";
import {
  Shield, LayoutDashboard, AlertTriangle, BarChart3,
  Users, Settings, LogOut, Wifi, WifiOff, Bell,
} from "lucide-react";
import { useState, useCallback } from "react";
import { useAuthStore } from "@/store/authStore";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import type { Incident } from "@/types";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/users", label: "Users", icon: Users },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Layout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [wsConnected, setWsConnected] = useState(false);
  const [liveAlerts, setLiveAlerts] = useState<{ id: number; risk: string; type: string }[]>([]);

  const handleNewIncident = useCallback(
    (data: Record<string, unknown>) => {
      const inc = data as Partial<Incident>;
      const risk = String(inc.risk_level ?? "Low");
      const type = String(inc.alert_type ?? "Unknown");
      const id = Number(inc.id);

      setLiveAlerts((prev) => [{ id, risk, type }, ...prev.slice(0, 4)]);

      const msg = `🚨 ${risk} incident #${id}: ${type}`;
      if (risk === "Critical" || risk === "High") {
        toast.error(msg, { duration: 6000 });
      } else {
        toast(msg, { duration: 6000 });
      }

      // Refresh queries
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
    },
    [navigate, queryClient]
  );

  useWebSocket({
    connected: () => setWsConnected(true),
    new_incident: handleNewIncident,
    incident_updated: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 flex flex-col bg-slate-900 border-r border-slate-800">
        {/* Logo */}
        <div className="p-5 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center">
            <Shield size={20} className="text-white" />
          </div>
          <div>
            <p className="font-bold text-sm text-white leading-tight">AI-NDR Platform</p>
            <p className="text-xs text-slate-500">Threat Detection</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors
                ${isActive
                  ? "bg-blue-600 text-white"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800"
                }`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Live Feed mini-indicator */}
        {liveAlerts.length > 0 && (
          <div className="mx-3 mb-2 p-3 bg-slate-800 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Bell size={13} className="text-yellow-400" />
              <span className="text-xs font-semibold text-slate-300">Live Alerts</span>
            </div>
            {liveAlerts.slice(0, 3).map((a) => (
              <button
                key={a.id}
                onClick={() => navigate(`/incidents/${a.id}`)}
                className="w-full text-left text-xs text-slate-400 hover:text-slate-200 py-0.5 truncate"
              >
                #{a.id} · {a.risk} · {a.type}
              </button>
            ))}
          </div>
        )}

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 space-y-2">
          {/* WS status */}
          <div className="flex items-center gap-2 px-3 py-1.5">
            {wsConnected ? (
              <Wifi size={14} className="text-green-400" />
            ) : (
              <WifiOff size={14} className="text-slate-600" />
            )}
            <span className={`text-xs ${wsConnected ? "text-green-400" : "text-slate-600"}`}>
              {wsConnected ? "Live feed active" : "Connecting..."}
            </span>
          </div>

          {/* User + logout */}
          <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-800">
            <div className="w-7 h-7 rounded-full bg-blue-700 flex items-center justify-center text-xs font-bold">
              {user?.full_name?.[0]?.toUpperCase() ?? "U"}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-slate-200 truncate">{user?.full_name}</p>
              <p className="text-xs text-slate-500 capitalize">{user?.role}</p>
            </div>
            <button onClick={handleLogout} className="text-slate-500 hover:text-red-400 transition-colors">
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
