import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import Icon from "../components/Icon";
import { clearAuthSession, getAuthHeaders, setAuthSession } from "../lib/auth";
import { API_BASE } from "../lib/api";

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const redirectPath = useMemo(() => {
    const candidate = location.state?.from;
    if (typeof candidate === "string" && candidate.startsWith("/")) {
      return candidate;
    }
    return "/dashboard";
  }, [location.state]);

  useEffect(() => {
    let cancelled = false;

    async function detectAccessMode() {
      setLoading(true);
      setError("");
      try {
        const anonymous = await fetch(`${API_BASE}/health/`);
        if (cancelled) return;
        if (anonymous.status === 200) {
          navigate("/dashboard", { replace: true });
          return;
        }

        if (anonymous.status === 401) {
          const withStoredToken = await fetch(`${API_BASE}/health/`, {
            headers: getAuthHeaders(),
          });
          if (cancelled) return;
          if (withStoredToken.status === 200) {
            navigate(redirectPath, { replace: true });
            return;
          }
          clearAuthSession();
        }
      } catch {
        // Keep login screen visible when API is unavailable.
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    detectAccessMode();

    return () => {
      cancelled = true;
    };
  }, [navigate, redirectPath]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    const trimmedUser = username.trim();
    if (!trimmedUser || !password) {
      setError("Username and password are required.");
      return;
    }

    setSubmitting(true);
    setAuthSession(trimmedUser, password);

    try {
      const response = await fetch(`${API_BASE}/health/`, {
        headers: getAuthHeaders(),
      });
      if (response.status === 200) {
        navigate(redirectPath, { replace: true });
        return;
      }
      clearAuthSession();
      setError("Invalid credentials.");
    } catch {
      clearAuthSession();
      setError("Unable to reach API.");
    } finally {
      setSubmitting(false);
    }
  }

  const inputClass =
    "bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary transition-colors";

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg bg-grid">
      <div className="w-full max-w-sm animate-fade-in">
        <div className="bg-white border border-neutral-200 rounded-2xl p-8 shadow-xl">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-4">
              <Icon name="hub" size={28} className="text-primary" />
            </div>
            <h1 className="text-xl font-bold text-slate-900">
              VPC Flow Log Analyzer
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              Sign in when optional API auth is enabled
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <label className="flex flex-col gap-1.5">
              <span className="text-xs text-slate-500 font-medium">
                Username
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin@company.com"
                className={inputClass}
              />
            </label>

            <label className="flex flex-col gap-1.5">
              <span className="text-xs text-slate-500 font-medium">
                Password
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className={inputClass}
              />
            </label>

            {error && (
              <div className="px-3 py-2 rounded-lg border border-red-200 bg-red-50 text-xs text-red-700">
                {error}
              </div>
            )}

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="rounded border-neutral-300 accent-primary"
                />
                <span className="text-xs text-slate-500">Remember me</span>
              </label>
              <a
                href="#"
                className="text-xs text-primary hover:text-primary-dark transition-colors"
              >
                Forgot password?
              </a>
            </div>

            <button
              type="submit"
              disabled={loading || submitting}
              className="w-full bg-primary hover:bg-primary-dark text-white font-semibold py-2.5 rounded-lg text-sm transition-colors mt-2 shadow-lg shadow-primary/20"
            >
              {loading ? "Checking..." : submitting ? "Signing In..." : "Sign In"}
            </button>
          </form>

          {/* Divider */}
          <div className="flex items-center gap-3 my-6">
            <div className="flex-1 h-px bg-neutral-200" />
            <span className="text-xs text-slate-400">or</span>
            <div className="flex-1 h-px bg-neutral-200" />
          </div>

          {/* SSO */}
          <button
            type="button"
            onClick={() => navigate("/dashboard")}
            className="w-full flex items-center justify-center gap-2 border border-neutral-300 rounded-lg py-2.5 text-sm text-slate-600 hover:text-slate-900 hover:bg-neutral-50 transition-colors"
          >
            <Icon name="key" size={16} />
            Continue
          </button>
        </div>

        <p className="text-center text-xs text-slate-400 mt-4">
          AWS VPC Flow Log Analysis Platform
        </p>
      </div>
    </div>
  );
}
