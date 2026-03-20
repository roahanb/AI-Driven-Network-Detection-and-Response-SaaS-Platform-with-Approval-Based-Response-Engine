import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { authApi } from "@/api/auth";
import toast from "react-hot-toast";

export default function RegisterPage() {
  const [form, setForm] = useState({
    email: "",
    full_name: "",
    password: "",
    organization_name: "",
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form.password.length < 8) {
      toast.error("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    try {
      await authApi.register(form);
      toast.success("Organization registered! Please sign in.");
      navigate("/login");
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? "Registration failed";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-14 h-14 bg-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Shield size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">Create Organization</h1>
          <p className="text-slate-400 mt-1">Set up your AI-NDR workspace</p>
        </div>

        <form onSubmit={handleSubmit} className="card space-y-4">
          {[
            { key: "organization_name", label: "Organization Name", placeholder: "Acme Corp Security", type: "text" },
            { key: "full_name", label: "Your Full Name", placeholder: "Jane Smith", type: "text" },
            { key: "email", label: "Work Email", placeholder: "jane@acme.com", type: "email" },
            { key: "password", label: "Password (min 8 chars)", placeholder: "••••••••", type: "password" },
          ].map(({ key, label, placeholder, type }) => (
            <div key={key}>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">{label}</label>
              <input
                type={type}
                className="input"
                placeholder={placeholder}
                value={form[key as keyof typeof form]}
                onChange={set(key as keyof typeof form)}
                required
              />
            </div>
          ))}

          <button type="submit" className="btn-primary w-full" disabled={loading}>
            {loading ? "Creating..." : "Create Organization"}
          </button>

          <p className="text-center text-sm text-slate-500">
            Already have an account?{" "}
            <Link to="/login" className="text-blue-400 hover:text-blue-300">Sign in</Link>
          </p>
        </form>
      </div>
    </div>
  );
}
