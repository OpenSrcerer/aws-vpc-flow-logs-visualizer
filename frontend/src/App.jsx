import { lazy, Suspense, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import AppLayout from "./layouts/AppLayout";
import { clearAuthSession, getAuthHeaders } from "./lib/auth";
import { API_BASE } from "./lib/api";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const WorkspacePage = lazy(() => import("./pages/WorkspacePage"));
const AssetsPage = lazy(() => import("./pages/AssetsPage"));
const LogsPage = lazy(() => import("./pages/LogsPage"));
const FirewallSimulatorPage = lazy(() => import("./pages/FirewallSimulatorPage"));
const SearchPage = lazy(() => import("./pages/SearchPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-text-muted text-sm">Loading...</div>
    </div>
  );
}

function AuthGate({ children }) {
  const location = useLocation();
  const [status, setStatus] = useState("checking");

  useEffect(() => {
    let cancelled = false;

    async function validateAccess() {
      setStatus("checking");
      try {
        const response = await fetch(`${API_BASE}/health/`, {
          headers: getAuthHeaders(),
        });
        if (cancelled) return;

        if (response.status === 200) {
          setStatus("allowed");
          return;
        }
        if (response.status === 401) {
          clearAuthSession();
          setStatus("denied");
          return;
        }
        setStatus("allowed");
      } catch {
        if (!cancelled) {
          setStatus("allowed");
        }
      }
    }

    validateAccess();

    return () => {
      cancelled = true;
    };
  }, [location.pathname, location.search]);

  if (status === "checking") {
    return <PageLoader />;
  }

  if (status === "denied") {
    const from = `${location.pathname}${location.search}`;
    return <Navigate to="/login" replace state={{ from }} />;
  }

  return children;
}

export default function App() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<AuthGate><AppLayout /></AuthGate>}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/workspace" element={<WorkspacePage />} />
          <Route path="/firewall-simulator" element={<FirewallSimulatorPage />} />
          <Route path="/search" element={<SearchPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Suspense>
  );
}
