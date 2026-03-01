import Icon from "../Icon";
import { formatBytes, formatInt } from "../../lib/graph";

const PROTOCOL_NAMES = { 1: "ICMP", 6: "TCP", 17: "UDP" };

function ActionBadge({ action }) {
  const isAccept = action === "ACCEPT";
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
        isAccept
          ? "bg-success/10 text-success"
          : "bg-danger/10 text-danger"
      }`}
    >
      {action}
    </span>
  );
}

export default function FlowLogsTable({
  flowLogs,
  page,
  totalCount,
  pageSize,
  onPageChange,
}) {
  const totalPages = Math.ceil(totalCount / pageSize);

  return (
    <div className="flex flex-col h-full bg-white rounded-xl border border-neutral-200 overflow-hidden shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-neutral-200 bg-neutral-50/50">
        <span className="text-sm font-medium text-slate-900">Flow Logs</span>
        <span className="text-xs text-slate-500">
          {totalCount > 0
            ? `Showing ${(page - 1) * pageSize + 1}-${Math.min(
                page * pageSize,
                totalCount
              )} of ${formatInt(totalCount)} results`
            : "No results"}
        </span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-neutral-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="text-left font-medium px-3 py-2">Timestamp</th>
              <th className="text-left font-medium px-3 py-2">Status</th>
              <th className="text-left font-medium px-3 py-2">Source</th>
              <th className="text-left font-medium px-3 py-2">Destination</th>
              <th className="text-left font-medium px-3 py-2">Protocol</th>
              <th className="text-right font-medium px-3 py-2">Packets</th>
              <th className="text-right font-medium px-3 py-2">Bytes</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-200">
            {flowLogs.map((log) => (
              <tr
                key={log.id}
                className="hover:bg-neutral-50 transition-colors"
              >
                <td className="px-3 py-2 text-slate-500 whitespace-nowrap">
                  {new Date(log.start_time).toLocaleString()}
                </td>
                <td className="px-3 py-2">
                  <ActionBadge action={log.action} />
                </td>
                <td className="px-3 py-2 text-slate-900 font-mono">
                  {log.srcaddr}
                  {log.srcport != null && (
                    <span className="text-slate-400">:{log.srcport}</span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-900 font-mono">
                  {log.dstaddr}
                  {log.dstport != null && (
                    <span className="text-slate-400">:{log.dstport}</span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-500">
                  {PROTOCOL_NAMES[log.protocol] || log.protocol}
                </td>
                <td className="px-3 py-2 text-right text-slate-500">
                  {formatInt(log.packets)}
                </td>
                <td className="px-3 py-2 text-right text-slate-500">
                  {formatBytes(log.bytes)}
                </td>
              </tr>
            ))}
            {flowLogs.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-8 text-center text-slate-400"
                >
                  No flow logs found. Upload logs to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-2 border-t border-neutral-200 bg-neutral-50/50">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-500 hover:text-slate-900 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Icon name="chevron_left" size={16} />
            Previous
          </button>
          <span className="text-xs text-slate-500">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-500 hover:text-slate-900 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Next
            <Icon name="chevron_right" size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
