import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { formatBytes, formatInt } from "../lib/graph";

const PROTOCOL_NAMES = {
  1: "ICMP",
  4: "IPIP",
  6: "TCP",
  17: "UDP",
};

function formatTags(tags) {
  if (!tags) return "";
  if (Array.isArray(tags)) {
    return tags.map((item) => String(item || "").trim()).filter(Boolean).join(", ");
  }
  if (typeof tags === "object") {
    return Object.entries(tags)
      .map(([key, value]) => (value ? `${key}=${value}` : key))
      .join(", ");
  }
  return String(tags);
}

function formatCidrs(group) {
  const cidrs = Array.isArray(group?.cidrs) && group.cidrs.length
    ? group.cidrs
    : group?.cidr
      ? [group.cidr]
      : [];
  return cidrs.join(", ");
}

function EmptyState({ text }) {
  return <div className="px-3 py-6 text-xs text-slate-400">{text}</div>;
}

export default function SearchPage() {
  const [searchParams] = useSearchParams();
  const query = String(searchParams.get("q") || "").trim();

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState({
    query: "",
    limit: 50,
    counts: {
      flow_logs: 0,
      correlated_flows: 0,
      ip_metadata: 0,
      network_groups: 0,
    },
    results: {
      flow_logs: [],
      correlated_flows: [],
      ip_metadata: [],
      network_groups: [],
    },
  });

  useEffect(() => {
    if (!query) {
      setPayload((current) => ({
        ...current,
        query: "",
        counts: {
          flow_logs: 0,
          correlated_flows: 0,
          ip_metadata: 0,
          network_groups: 0,
        },
        results: {
          flow_logs: [],
          correlated_flows: [],
          ip_metadata: [],
          network_groups: [],
        },
      }));
      setError("");
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError("");
    api.searchEverything(query, 50)
      .then((response) => {
        if (cancelled) return;
        setPayload(response);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err.message || "Search failed");
        setPayload((current) => ({
          ...current,
          query,
          counts: {
            flow_logs: 0,
            correlated_flows: 0,
            ip_metadata: 0,
            network_groups: 0,
          },
          results: {
            flow_logs: [],
            correlated_flows: [],
            ip_metadata: [],
            network_groups: [],
          },
        }));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [query]);

  const flowLogs = payload?.results?.flow_logs || [];
  const correlatedFlows = payload?.results?.correlated_flows || [];
  const ipMetadata = payload?.results?.ip_metadata || [];
  const networkGroups = payload?.results?.network_groups || [];

  return (
    <div className="max-w-7xl mx-auto p-6 flex flex-col gap-3">
      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Global Search</h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Search anything: IPs, ports, protocols, tags, names, groups, and flow metadata.
        </p>
        <p className="text-xs text-slate-500 mt-2">
          Query: <span className="font-medium text-slate-700">{query || "(empty)"}</span>
        </p>
      </div>

      {error && (
        <div className="px-3 py-2 text-xs text-danger bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Flow Logs</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{formatInt(payload?.counts?.flow_logs || 0)}</div>
        </div>
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Correlated</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{formatInt(payload?.counts?.correlated_flows || 0)}</div>
        </div>
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Assets</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{formatInt(payload?.counts?.ip_metadata || 0)}</div>
        </div>
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Groups</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{formatInt(payload?.counts?.network_groups || 0)}</div>
        </div>
      </div>

      {loading && (
        <div className="bg-white border border-neutral-200 rounded-2xl p-8 text-center text-sm text-slate-500">
          Searching...
        </div>
      )}

      {!loading && !query && (
        <div className="bg-white border border-neutral-200 rounded-2xl p-8 text-center text-sm text-slate-500">
          Enter a query in the header search box.
        </div>
      )}

      {!loading && query && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <section className="bg-white border border-neutral-200 rounded-2xl shadow-sm overflow-hidden">
            <div className="px-3 py-2 border-b border-neutral-200 text-xs font-semibold uppercase tracking-wider text-slate-600">
              Flow Logs
            </div>
            {flowLogs.length === 0 ? (
              <EmptyState text="No flow log matches." />
            ) : (
              <div className="max-h-80 overflow-auto divide-y divide-neutral-200">
                {flowLogs.map((row) => (
                  <div key={`flow-${row.id}`} className="px-3 py-2 text-xs">
                    <div className="text-slate-800 font-medium font-mono">
                      {row.srcaddr}:{row.srcport ?? "-"} {"->"} {row.dstaddr}:{row.dstport ?? "-"}
                    </div>
                    <div className="text-slate-500 mt-0.5">
                      {PROTOCOL_NAMES[row.protocol] || row.protocol} · {row.action} · {row.source || "manual"}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="bg-white border border-neutral-200 rounded-2xl shadow-sm overflow-hidden">
            <div className="px-3 py-2 border-b border-neutral-200 text-xs font-semibold uppercase tracking-wider text-slate-600">
              Correlated Flows
            </div>
            {correlatedFlows.length === 0 ? (
              <EmptyState text="No correlated flow matches." />
            ) : (
              <div className="max-h-80 overflow-auto divide-y divide-neutral-200">
                {correlatedFlows.map((row) => (
                  <div key={`corr-${row.id}`} className="px-3 py-2 text-xs">
                    <div className="text-slate-800 font-medium font-mono">
                      {row.client_ip}:{row.client_port ?? "-"} {"->"} {row.server_ip}:{row.server_port ?? "-"}
                    </div>
                    <div className="text-slate-500 mt-0.5">
                      {PROTOCOL_NAMES[row.protocol] || row.protocol} · {formatInt(row.flow_count)} sessions · {formatBytes((row.c2s_bytes || 0) + (row.s2c_bytes || 0))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="bg-white border border-neutral-200 rounded-2xl shadow-sm overflow-hidden">
            <div className="px-3 py-2 border-b border-neutral-200 text-xs font-semibold uppercase tracking-wider text-slate-600">
              Assets
            </div>
            {ipMetadata.length === 0 ? (
              <EmptyState text="No asset matches." />
            ) : (
              <div className="max-h-80 overflow-auto divide-y divide-neutral-200">
                {ipMetadata.map((row) => (
                  <div key={`asset-${row.id}`} className="px-3 py-2 text-xs">
                    <div className="text-slate-800 font-medium">
                      {row.name || "(unnamed)"} <span className="font-mono text-slate-500">({row.ip_address})</span>
                    </div>
                    <div className="text-slate-500 mt-0.5">
                      {(row.asset_kind || "UNKNOWN").toString()} · {row.account_owner || row.provider || "n/a"}
                    </div>
                    {!!formatTags(row.tags) && (
                      <div className="text-slate-500 mt-0.5 truncate">Tags: {formatTags(row.tags)}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="bg-white border border-neutral-200 rounded-2xl shadow-sm overflow-hidden">
            <div className="px-3 py-2 border-b border-neutral-200 text-xs font-semibold uppercase tracking-wider text-slate-600">
              Network Groups
            </div>
            {networkGroups.length === 0 ? (
              <EmptyState text="No network group matches." />
            ) : (
              <div className="max-h-80 overflow-auto divide-y divide-neutral-200">
                {networkGroups.map((row) => (
                  <div key={`group-${row.id}`} className="px-3 py-2 text-xs">
                    <div className="text-slate-800 font-medium">
                      {row.name} <span className="text-slate-500">({row.kind || "CUSTOM"})</span>
                    </div>
                    <div className="text-slate-500 mt-0.5 truncate font-mono">{formatCidrs(row)}</div>
                    {!!formatTags(row.tags) && (
                      <div className="text-slate-500 mt-0.5 truncate">Tags: {formatTags(row.tags)}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {!loading && query && (
        <div className="text-xs text-slate-500">
          Tip: refine by protocol names (`tcp`, `udp`, `icmp`, `ipip`), exact IPs, ports, tags, or group names.
          {" "}
          <Link className="text-primary hover:text-primary-dark" to="/logs">
            Open Logs
          </Link>
          {" · "}
          <Link className="text-primary hover:text-primary-dark" to="/assets">
            Open Assets
          </Link>
        </div>
      )}
    </div>
  );
}
