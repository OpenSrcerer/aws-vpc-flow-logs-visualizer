import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, extractResults } from "../lib/api";
import { formatBytes, formatInt } from "../lib/graph";
import Icon from "../components/Icon";

const PROTOCOL_LABELS = { 1: "ICMP", 6: "TCP", 17: "UDP" };

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [health, setHealth] = useState(null);
  const [mesh, setMesh] = useState({ nodes: [], edges: [] });
  const [correlatedFlows, setCorrelatedFlows] = useState([]);

  const fetchDashboard = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [healthRes, meshRes, correlatedRes] = await Promise.all([
        api.getHealth(),
        api.getMesh(),
        api.listCorrelatedFlows(),
      ]);
      setHealth(healthRes);
      setMesh(meshRes);
      setCorrelatedFlows(extractResults(correlatedRes));
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message || "Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  const trafficSummary = useMemo(() => {
    const totalBytes = correlatedFlows.reduce(
      (acc, f) => acc + f.c2s_bytes + f.s2c_bytes,
      0
    );
    return { totalBytes };
  }, [correlatedFlows]);

  const protocolBreakdown = useMemo(() => {
    const byProtocol = {};
    for (const flow of correlatedFlows) {
      const key = String(flow.protocol);
      if (!byProtocol[key]) {
        byProtocol[key] = {
          protocol: PROTOCOL_LABELS[flow.protocol] || String(flow.protocol),
          bytes: 0,
        };
      }
      byProtocol[key].bytes += flow.c2s_bytes + flow.s2c_bytes;
    }
    return Object.values(byProtocol).sort((a, b) => b.bytes - a.bytes).slice(0, 6);
  }, [correlatedFlows]);

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
      },
      {
        label: "Correlated Sessions",
        value: formatInt(health?.correlated_flows ?? 0),
        icon: "link",
      },
      {
        label: "IP Assets",
        value: formatInt(health?.ip_metadata ?? 0),
        icon: "dns",
      },
      {
        label: "Network Groups",
        value: formatInt(health?.network_groups ?? 0),
        icon: "account_tree",
      },
      {
        label: "Observed Traffic",
        value: formatBytes(trafficSummary.totalBytes),
        icon: "data_usage",
      },
    ],
    [health, trafficSummary.totalBytes]
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
            <button
              onClick={fetchDashboard}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
            >
              <Icon name="refresh" size={14} />
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
              {loading ? "..." : metric.value}
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
          {topConversations.length === 0 ? (
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
          {protocolBreakdown.length === 0 ? (
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
        {topServices.length === 0 ? (
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
