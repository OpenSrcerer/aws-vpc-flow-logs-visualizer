import { useCallback, useEffect, useMemo, useState } from "react";
import { api, extractResults } from "../lib/api";
import { formatBytes, formatInt } from "../lib/graph";
import Icon from "../components/Icon";
import FiltersSidebar from "../components/workspace/FiltersSidebar";
import TopologyPanel from "../components/workspace/TopologyPanel";
import FlowLogsTable from "../components/workspace/FlowLogsTable";

export default function WorkspacePage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [health, setHealth] = useState(null);
  const [mesh, setMesh] = useState({ nodes: [], edges: [] });
  const [correlatedFlows, setCorrelatedFlows] = useState([]);

  const [flowLogs, setFlowLogs] = useState([]);
  const [flowLogCount, setFlowLogCount] = useState(0);
  const [flowLogPage, setFlowLogPage] = useState(1);
  const [filters, setFilters] = useState({});

  const [showLogs, setShowLogs] = useState(false);
  const [showFilters, setShowFilters] = useState(false);

  const PAGE_SIZE = 50;

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
    } catch (err) {
      setError(err.message || "Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchFlowLogs = useCallback(
    async (page = 1, activeFilters = filters) => {
      try {
        const res = await api.listFlowLogs({
          ...activeFilters,
          page,
          page_size: PAGE_SIZE,
        });
        setFlowLogs(extractResults(res));
        setFlowLogCount(res?.count ?? extractResults(res).length);
        setFlowLogPage(page);
      } catch (err) {
        setError(err.message || "Failed to load flow logs");
      }
    },
    [filters]
  );

  useEffect(() => {
    fetchDashboard();
    fetchFlowLogs(1, {});
  }, []);

  function handleApplyFilters(newFilters) {
    setFilters(newFilters);
    fetchFlowLogs(1, newFilters);
  }

  function handlePageChange(page) {
    fetchFlowLogs(page, filters);
  }

  const trafficSummary = useMemo(() => {
    const totalBytes = correlatedFlows.reduce(
      (acc, f) => acc + f.c2s_bytes + f.s2c_bytes,
      0
    );
    return { totalBytes };
  }, [correlatedFlows]);

  return (
    <div className="flex h-[calc(100vh-3.25rem)]">
      {showFilters && (
        <FiltersSidebar filters={filters} onApply={handleApplyFilters} />
      )}

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-neutral-200 bg-white shrink-0">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`p-1.5 rounded-lg text-sm transition-colors ${
              showFilters
                ? "bg-primary/10 text-primary"
                : "text-slate-500 hover:text-slate-900 hover:bg-neutral-100"
            }`}
            title="Toggle filters"
          >
            <Icon name="filter_list" size={18} />
          </button>

          <div className="w-px h-5 bg-slate-200" />

          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Icon name="stacks" size={14} className="text-primary" />
            <span className="font-medium text-slate-700">{formatInt(health?.flow_log_entries ?? 0)}</span>
            <span>flows</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Icon name="data_usage" size={14} className="text-primary" />
            <span className="font-medium text-slate-700">{formatBytes(trafficSummary.totalBytes)}</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Icon name="link" size={14} className="text-primary" />
            <span className="font-medium text-slate-700">{formatInt(health?.correlated_flows ?? 0)}</span>
            <span>sessions</span>
          </div>

          {error && (
            <span className="text-xs text-danger ml-2">{error}</span>
          )}

          <div className="flex-1" />

          <button
            onClick={() => setShowLogs(!showLogs)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition-colors ${
              showLogs
                ? "bg-primary/10 text-primary"
                : "text-slate-500 hover:text-slate-900 hover:bg-neutral-100"
            }`}
          >
            <Icon name="table_rows" size={16} />
            Flow Logs
            <Icon name={showLogs ? "expand_more" : "expand_less"} size={14} />
          </button>
        </div>

        <div className={`flex-1 min-h-0 ${showLogs ? "h-[55%]" : ""}`}>
          <TopologyPanel mesh={mesh} />
        </div>

        {showLogs && (
          <div className="h-[45%] min-h-0 border-t border-neutral-200">
            <FlowLogsTable
              flowLogs={flowLogs}
              page={flowLogPage}
              totalCount={flowLogCount}
              pageSize={PAGE_SIZE}
              onPageChange={handlePageChange}
            />
          </div>
        )}
      </div>
    </div>
  );
}
