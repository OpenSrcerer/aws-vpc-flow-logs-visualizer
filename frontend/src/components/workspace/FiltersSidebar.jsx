import { useState } from "react";
import Icon from "../Icon";

const PROTOCOLS = [
  { value: "", label: "All" },
  { value: "6", label: "TCP (6)" },
  { value: "17", label: "UDP (17)" },
  { value: "1", label: "ICMP (1)" },
  { value: "4", label: "IP-in-IP (4)" },
];

const TIME_RANGES = [
  { value: "", label: "All Time" },
  { value: "1h", label: "Last 1 Hour" },
  { value: "24h", label: "Last 24 Hours" },
  { value: "7d", label: "Last 7 Days" },
  { value: "30d", label: "Last 30 Days" },
];

function getTimeSince(range) {
  if (!range) return "";
  const now = new Date();
  const ms = { "1h": 3600000, "24h": 86400000, "7d": 604800000, "30d": 2592000000 };
  return new Date(now.getTime() - (ms[range] || 0)).toISOString();
}

export default function FiltersSidebar({ filters, onApply }) {
  const [srcaddr, setSrcaddr] = useState(filters.srcaddr || "");
  const [dstaddr, setDstaddr] = useState(filters.dstaddr || "");
  const [protocol, setProtocol] = useState(filters.protocol || "");
  const [action, setAction] = useState(filters.action || "");
  const [timeRange, setTimeRange] = useState("");

  function handleApply(e) {
    e.preventDefault();
    onApply({
      srcaddr: srcaddr || undefined,
      dstaddr: dstaddr || undefined,
      protocol: protocol || undefined,
      action: action || undefined,
      since: getTimeSince(timeRange) || undefined,
    });
  }

  function handleReset() {
    setSrcaddr("");
    setDstaddr("");
    setProtocol("");
    setAction("");
    setTimeRange("");
    onApply({});
  }

  const inputClass =
    "bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary";

  return (
    <aside className="w-64 shrink-0 bg-white border-r border-neutral-200 overflow-y-auto p-4 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-900">Filters</h3>
        <button
          onClick={handleReset}
          className="text-xs text-slate-500 hover:text-primary transition-colors"
        >
          Reset All
        </button>
      </div>

      <form onSubmit={handleApply} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-slate-500 font-medium">Source IP</span>
          <input
            value={srcaddr}
            onChange={(e) => setSrcaddr(e.target.value)}
            placeholder="e.g. 10.0.1.10"
            className={inputClass}
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-slate-500 font-medium">Destination IP</span>
          <input
            value={dstaddr}
            onChange={(e) => setDstaddr(e.target.value)}
            placeholder="e.g. 10.0.2.20"
            className={inputClass}
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-slate-500 font-medium">Protocol</span>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            className={inputClass}
          >
            {PROTOCOLS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-slate-500 font-medium">Action</span>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className={inputClass}
          >
            <option value="">All</option>
            <option value="ACCEPT">ACCEPT</option>
            <option value="REJECT">REJECT</option>
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-slate-500 font-medium">Time Range</span>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className={inputClass}
          >
            {TIME_RANGES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </label>

        <button
          type="submit"
          className="mt-2 w-full bg-primary hover:bg-primary-dark text-white font-semibold py-2 rounded-lg text-sm transition-colors flex items-center justify-center gap-1.5 shadow-lg shadow-primary/20"
        >
          <Icon name="filter_list" size={16} />
          Apply Filters
        </button>
      </form>
    </aside>
  );
}
