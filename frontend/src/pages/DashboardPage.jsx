import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { formatBytes, formatInt } from "../lib/graph";
import Icon from "../components/Icon";

const PROTOCOL_LABELS = { 1: "ICMP", 4: "IPIP", 6: "TCP", 17: "UDP" };

function SkeletonRow() {
  return (
    <div className="flex items-center justify-between gap-3 py-0.5 animate-pulse">
      <div className="h-3 rounded bg-slate-200 w-2/3" />
      <div className="h-3 rounded bg-slate-200 w-16" />
    </div>
  );
}

function SkeletonMetric() {
  return <div className="h-5 mt-1 rounded bg-slate-200 w-20 animate-pulse" />;
}

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [loadingState, setLoadingState] = useState({
    health: true,
    mesh: true,
    summary: true,
  });
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [health, setHealth] = useState(null);
  const [mesh, setMesh] = useState({ nodes: [], edges: [] });
  const [summary, setSummary] = useState({
    traffic: { total_bytes: 0, total_packets: 0, total_sessions: 0 },
    protocol_breakdown: [],
  });

  const fetchDashboard = useCallback(async () => {
    setLoading(true);
    setError("");
    setLoadingState({ health: true, mesh: true, summary: true });

    const errors = [];
    let hadSuccess = false;

    const healthRequest = api.getHealth()
      .then((healthRes) => {
        hadSuccess = true;
        setHealth(healthRes);
      })
      .catch((err) => {
        errors.push(`Health: ${err.message || "request failed"}`);
      })
      .finally(() => {
        setLoadingState((current) => ({ ...current, health: false }));
      });

    const meshRequest = api.getMesh()
      .then((meshRes) => {
        hadSuccess = true;
        setMesh(meshRes || { nodes: [], edges: [] });
      })
      .catch((err) => {
        errors.push(`Topology: ${err.message || "request failed"}`);
      })
      .finally(() => {
        setLoadingState((current) => ({ ...current, mesh: false }));
      });

    const summaryRequest = api.getDashboardSummary()
      .then((summaryRes) => {
        hadSuccess = true;
        setSummary(summaryRes || {
          traffic: { total_bytes: 0, total_packets: 0, total_sessions: 0 },
          protocol_breakdown: [],
        });
      })
      .catch((err) => {
        errors.push(`Summary: ${err.message || "request failed"}`);
      })
      .finally(() => {
        setLoadingState((current) => ({ ...current, summary: false }));
      });

    await Promise.all([healthRequest, meshRequest, summaryRequest]);

    if (errors.length > 0) {
      setError(errors.join(" | "));
    }
    if (hadSuccess) {
      setLastUpdated(new Date());
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  const trafficSummary = useMemo(() => {
    return { totalBytes: summary?.traffic?.total_bytes || 0 };
  }, [summary]);

  const protocolBreakdown = useMemo(() => {
    const rows = Array.isArray(summary?.protocol_breakdown)
      ? summary.protocol_breakdown
      : [];
    return rows
      .map((row) => ({
        protocol: PROTOCOL_LABELS[row.protocol] || String(row.protocol),
        bytes: row.bytes || 0,
      }))
      .slice(0, 6);
  }, [summary]);

  const topConversations = useMemo(
    () =>
      [...(mesh?.edges || [])]
        .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
        .slice(0, 6),
    [mesh]
  );

  const topServices = useMemo(() => {
    const aggregate = {};
    for (const edge of mesh?.edges || []) {
      const protocolLabel =
        PROTOCOL_LABELS[edge.protocol] ||
        edge.protocol_name ||
        String(edge.protocol ?? "*");
      const portValue = edge.port ?? "*";
      const serviceIp = edge.target || "";
      const serviceLabel = edge.target_label || serviceIp || "Unknown";
      const key = `${serviceIp}|${protocolLabel}|${portValue}`;

      if (!aggregate[key]) {
        aggregate[key] = {
          key,
          serviceLabel,
          serviceIp,
          protocolLabel,
          portValue,
          bytes: 0,
          packets: 0,
          flows: 0,
          clients: new Set(),
        };
      }

      aggregate[key].bytes += edge.bytes || 0;
      aggregate[key].packets += edge.packets || 0;
      aggregate[key].flows += edge.flows || 0;
      if (edge.source) {
        aggregate[key].clients.add(edge.source);
      }
    }

    return Object.values(aggregate)
      .map((item) => ({
        ...item,
        clientCount: item.clients.size,
      }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 9);
  }, [mesh]);

  const metrics = useMemo(
    () => [
      {
        label: "Raw Flows",
        value: formatInt(health?.flow_log_entries ?? 0),
        icon: "stacks",
        dataLoading: loadingState.health,
      },
      {
        label: "Correlated Sessions",
        value: formatInt(health?.correlated_flows ?? 0),
        icon: "link",
        dataLoading: loadingState.health,
      },
      {
        label: "IP Assets",
        value: formatInt(health?.ip_metadata ?? 0),
        icon: "dns",
        dataLoading: loadingState.health,
      },
      {
        label: "Network Groups",
        value: formatInt(health?.network_groups ?? 0),
        icon: "account_tree",
        dataLoading: loadingState.health,
      },
      {
        label: "Observed Traffic",
        value: formatBytes(trafficSummary.totalBytes),
        icon: "data_usage",
        dataLoading: loadingState.summary,
      },
    ],
    [health, loadingState.health, loadingState.summary, trafficSummary.totalBytes]
  );

  return (
    <div className="max-w-7xl mx-auto p-6 flex flex-col gap-3">
      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Dashboard</h2>
            <p className="text-sm text-slate-500">
              Aggregated traffic and topology summary.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500">
              Updated: <span className="font-medium text-slate-700">{lastUpdated ? lastUpdated.toLocaleTimeString() : "-"}</span>
            </span>
            {loading && (
              <span className="inline-flex items-center gap-1 text-xs text-slate-500">
                <Icon name="refresh" size={12} className="animate-spin" />
                Loading data...
              </span>
            )}
            <button
              onClick={fetchDashboard}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
            >
              <Icon name="refresh" size={14} className={loading ? "animate-spin" : ""} />
              Refresh
            </button>
            <Link
              to="/workspace"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-primary hover:bg-primary-dark transition-colors"
            >
              <Icon name="hub" size={14} />
              Open Map View
            </Link>
          </div>
        </div>
      </div>

      {error && (
        <div className="px-3 py-2 text-xs text-danger bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-2">
        {metrics.map((metric) => (
          <div
            key={metric.label}
            className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">
                {metric.label}
              </span>
              <Icon name={metric.icon} size={14} className="text-primary" />
            </div>
            <div className="text-base font-semibold text-slate-900 mt-1 truncate">
              {metric.dataLoading ? <SkeletonMetric /> : metric.value}
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-2">
        <div className="bg-white border border-neutral-200 rounded-xl p-3 shadow-sm xl:col-span-2">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold text-slate-700 uppercase tracking-wider">
              Top Conversations
            </h3>
            <span className="text-[11px] text-slate-400">By bytes</span>
          </div>
          {loadingState.mesh ? (
            <div className="space-y-1.5 py-0.5">
              {Array.from({ length: 6 }).map((_, idx) => (
                <SkeletonRow key={`top-conv-skeleton-${idx}`} />
              ))}
            </div>
          ) : topConversations.length === 0 ? (
            <p className="text-xs text-slate-400 py-3">No correlated traffic yet.</p>
          ) : (
            <div className="space-y-1.5">
              {topConversations.map((edge, idx) => (
                <div
                  key={`${edge.source}-${edge.target}-${edge.port}-${idx}`}
                  className="flex items-center justify-between text-xs"
                >
                  <div className="truncate pr-2 text-slate-700">
                    <span className="font-medium">{edge.source_label || edge.source}</span>
                    <span className="text-slate-400 px-1">→</span>
                    <span className="font-medium">{edge.target_label || edge.target}</span>
                    <span className="text-slate-400 ml-1">
                      ({(PROTOCOL_LABELS[edge.protocol] || edge.protocol).toString()}:{edge.port ?? "*"})
                    </span>
                  </div>
                  <span className="text-slate-600 font-medium whitespace-nowrap">
                    {formatBytes(edge.bytes || 0)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-white border border-neutral-200 rounded-xl p-3 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold text-slate-700 uppercase tracking-wider">
              Protocol Mix
            </h3>
            <span className="text-[11px] text-slate-400">Top 6</span>
          </div>
          {loadingState.summary ? (
            <div className="space-y-1.5 py-0.5">
              {Array.from({ length: 6 }).map((_, idx) => (
                <SkeletonRow key={`protocol-skeleton-${idx}`} />
              ))}
            </div>
          ) : protocolBreakdown.length === 0 ? (
            <p className="text-xs text-slate-400 py-3">No protocol data yet.</p>
          ) : (
            <div className="space-y-1.5">
              {protocolBreakdown.map((row) => (
                <div key={row.protocol} className="flex items-center justify-between text-xs">
                  <span className="text-slate-700">{row.protocol}</span>
                  <span className="text-slate-600 font-medium whitespace-nowrap">
                    {formatBytes(row.bytes)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="bg-white border border-neutral-200 rounded-xl p-3 shadow-sm">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold text-slate-700 uppercase tracking-wider">
            Top Services
          </h3>
          <span className="text-[11px] text-slate-400">By service + port</span>
        </div>
        {loadingState.mesh ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-1.5">
            {Array.from({ length: 6 }).map((_, idx) => (
              <div
                key={`service-skeleton-${idx}`}
                className="px-2 py-1.5 rounded border border-neutral-200 bg-neutral-50/40 text-xs animate-pulse"
              >
                <div className="h-3 rounded bg-slate-200 w-2/3 mb-2" />
                <div className="h-3 rounded bg-slate-200 w-1/3 mb-2" />
                <div className="h-3 rounded bg-slate-200 w-full" />
              </div>
            ))}
          </div>
        ) : topServices.length === 0 ? (
          <p className="text-xs text-slate-400 py-3">No service data yet.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-1.5">
            {topServices.map((service) => (
              <div key={service.key} className="px-2 py-1.5 rounded border border-neutral-200 bg-neutral-50/40 text-xs">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div
                      className="text-slate-800 truncate font-medium"
                      title={service.serviceIp ? `${service.serviceLabel} (${service.serviceIp})` : service.serviceLabel}
                    >
                      {service.serviceLabel}
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                      {service.protocolLabel}:{service.portValue}
                    </div>
                  </div>
                  <div className="text-slate-700 font-medium whitespace-nowrap">
                    {formatBytes(service.bytes)}
                  </div>
                </div>
                <div className="mt-1 flex items-center gap-2.5 text-[11px] text-slate-500">
                  <span>{formatInt(service.flows)} flows</span>
                  <span>{formatInt(service.packets)} pkts</span>
                  <span>{formatInt(service.clientCount)} clients</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
