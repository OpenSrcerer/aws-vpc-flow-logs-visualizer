import { useMemo } from "react";

function getRowKey(item) {
  if (item?.id != null && item.id !== "") {
    return `id:${item.id}`;
  }
  return `ip:${item?.ip_address || ""}`;
}

function normalizeTagMap(value) {
  if (!value) return {};
  if (Array.isArray(value)) {
    const payload = {};
    value.forEach((item) => {
      const text = String(item || "").trim();
      if (!text) return;
      if (text.includes("=")) {
        const [key, ...rest] = text.split("=");
        payload[key.trim()] = rest.join("=").trim();
      } else {
        payload[text] = "";
      }
    });
    return payload;
  }
  if (typeof value === "object") {
    const payload = {};
    Object.entries(value).forEach(([key, tagValue]) => {
      const normalizedKey = String(key || "").trim();
      if (!normalizedKey) return;
      payload[normalizedKey] = tagValue == null ? "" : String(tagValue).trim();
    });
    return payload;
  }
  return {};
}

function renderTagChip(key, tagValue) {
  const content = tagValue ? `${key}=${tagValue}` : key;
  return (
    <span
      key={`${key}:${tagValue}`}
      className="inline-flex px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] max-w-48 truncate"
      title={content}
    >
      {content}
    </span>
  );
}

export default function AssetTable({ metadata, selectedId, onSelect }) {
  const sorted = useMemo(
    () =>
      [...metadata].sort((a, b) =>
        (a?.ip_address || "").localeCompare(b?.ip_address || "")
      ),
    [metadata]
  );

  return (
    <div className="flex flex-col h-full bg-white rounded-xl border border-neutral-200 overflow-hidden shadow-sm">
      <div className="flex items-center justify-between px-4 py-2 border-b border-neutral-200 bg-neutral-50/50">
        <span className="text-sm font-medium text-slate-900">
          IP Assets ({sorted.length})
        </span>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-neutral-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="text-left font-medium px-3 py-2">IP Address</th>
              <th className="text-left font-medium px-3 py-2">Resource Name</th>
              <th className="text-left font-medium px-3 py-2">Kind</th>
              <th className="text-left font-medium px-3 py-2">Instance / ENI</th>
              <th className="text-left font-medium px-3 py-2">Type / State</th>
              <th className="text-left font-medium px-3 py-2">Region / AZ</th>
              <th className="text-left font-medium px-3 py-2">Owner</th>
              <th className="text-left font-medium px-3 py-2">Tags</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-200">
            {sorted.map((item) => {
              const rowKey = getRowKey(item);
              const tags = normalizeTagMap(item.tags);
              const tagEntries = Object.entries(tags);
              const owner = item.account_owner || item.provider || (item._discovered ? "From flow logs" : "-");
              const instanceOrEni = [item.instance_id, item.interface_id].filter(Boolean).join(" / ");

              return (
                <tr
                  key={rowKey}
                  onClick={() => onSelect(rowKey)}
                  className={`cursor-pointer transition-colors ${
                    selectedId === rowKey ? "bg-primary/5" : "hover:bg-neutral-50"
                  }`}
                >
                  <td className="px-3 py-2 text-slate-900 font-mono">{item.ip_address}</td>
                  <td className="px-3 py-2 text-slate-600">
                    <div className="flex items-center gap-1.5">
                      <span>{item.name || "-"}</span>
                      {item._discovered && (
                        <span className="inline-flex px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px] font-medium">
                          Observed
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-slate-600">{item.asset_kind || "UNKNOWN"}</td>
                  <td className="px-3 py-2 text-slate-600 font-mono">{instanceOrEni || "-"}</td>
                  <td className="px-3 py-2 text-slate-600">
                    {[item.instance_type, item.state].filter(Boolean).join(" / ") || "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-600">
                    {[item.region, item.availability_zone].filter(Boolean).join(" / ") || "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-600">{owner}</td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1 flex-wrap">
                      {tagEntries.slice(0, 4).map(([key, tagValue]) => renderTagChip(key, tagValue))}
                      {tagEntries.length > 4 && (
                        <span className="inline-flex px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 text-[10px]">
                          +{tagEntries.length - 4}
                        </span>
                      )}
                      {tagEntries.length === 0 && <span className="text-slate-400">-</span>}
                    </div>
                  </td>
                </tr>
              );
            })}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-slate-400">
                  No assets found yet. Add an asset or ingest flow logs.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
