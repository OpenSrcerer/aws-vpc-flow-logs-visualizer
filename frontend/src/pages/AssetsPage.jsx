import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ipaddr from "ipaddr.js";
import { api, extractResults } from "../lib/api";
import HierarchySidebar from "../components/assets/HierarchySidebar";
import AssetTable from "../components/assets/AssetTable";
import MetadataEditorSidebar from "../components/assets/MetadataEditorSidebar";

function makeAssetKey(item) {
  if (!item) return "";
  if (item.id != null && item.id !== "") {
    return `id:${item.id}`;
  }
  return `ip:${item.ip_address || ""}`;
}

function getCidrs(group) {
  if (!group) return [];
  return Array.isArray(group.cidrs) && group.cidrs.length
    ? group.cidrs
    : group.cidr
      ? [group.cidr]
      : [];
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

export default function AssetsPage() {
  const [metadata, setMetadata] = useState([]);
  const [discoveredAssets, setDiscoveredAssets] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedGroupFilter, setSelectedGroupFilter] = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [loadProgress, setLoadProgress] = useState({ done: 0, total: 3 });
  const didInitFetchRef = useRef(false);

  const mergedAssets = useMemo(() => {
    const metadataByIp = new Set(
      metadata
        .map((item) => item.ip_address)
        .filter(Boolean)
    );

    const metadataRows = metadata.map((item) => ({
      ...item,
      _discovered: false,
    }));

    const discoveredRows = discoveredAssets
      .filter((item) => item.ip_address && !metadataByIp.has(item.ip_address))
      .map((item) => ({
        ...item,
        _discovered: true,
      }));

    const allRows = [...metadataRows, ...discoveredRows];

    if (!selectedGroupFilter) {
      return allRows;
    }

    const cidrStrings = getCidrs(selectedGroupFilter);
    const parsedCidrs = cidrStrings.map(c => {
      try {
        if (c.indexOf('/') === -1) {
          // It's a single IP, make it a /32 or /128
          return ipaddr.parseCIDR(c + (c.indexOf(':') !== -1 ? '/128' : '/32'));
        }
        return ipaddr.parseCIDR(c);
      } catch (e) {
        return null;
      }
    }).filter(Boolean);

    return allRows.filter(row => {
      if (!row.ip_address) return false;
      try {
        const parsedIp = ipaddr.parse(row.ip_address);
        return parsedCidrs.some(([range, bits]) => {
          try {
            return parsedIp.match(range, bits);
          } catch(e) {
            return false;
          }
        });
      } catch (e) {
        return false;
      }
    });
  }, [metadata, discoveredAssets, selectedGroupFilter]);

  const selected = useMemo(() => {
    if (!selectedKey) return null;
    return mergedAssets.find((item) => makeAssetKey(item) === selectedKey) || null;
  }, [mergedAssets, selectedKey]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    setLoadProgress({ done: 0, total: 3 });

    const track = (promise) =>
      promise.finally(() => {
        setLoadProgress((current) => ({
          ...current,
          done: Math.min(current.total, current.done + 1),
        }));
      });

    const [metaRes, groupsRes, meshRes] = await Promise.allSettled([
      track(api.listIpMetadata()),
      track(api.listNetworkGroups()),
      track(api.getMesh()),
    ]);

    const errors = [];

    if (metaRes.status === "fulfilled") {
      setMetadata(extractResults(metaRes.value));
    } else {
      setMetadata([]);
      errors.push(`IP metadata: ${metaRes.reason?.message || "request failed"}`);
    }

    if (groupsRes.status === "fulfilled") {
      setGroups(extractResults(groupsRes.value));
    } else {
      setGroups([]);
      errors.push(`Network groups: ${groupsRes.reason?.message || "request failed"}`);
    }

    if (meshRes.status === "fulfilled") {
      const nodes = Array.isArray(meshRes.value?.nodes) ? meshRes.value.nodes : [];
      const discovered = nodes
        .map((node) => ({
          id: null,
          ip_address: node.ip || node.id || "",
          name: node.label && node.label !== (node.ip || node.id) ? node.label : "",
          asset_kind: node.asset_kind || "UNKNOWN",
          instance_id: node.instance_id || "",
          interface_id: node.interface_id || "",
          instance_type: node.instance_type || "",
          state: node.state || "",
          region: node.region || "",
          availability_zone: node.availability_zone || "",
          account_owner: node.account_owner || "",
          provider: node.provider || "",
          tags: normalizeTagMap(node.tags),
          attributes: {},
        }))
        .filter((item) => item.ip_address);
      setDiscoveredAssets(discovered);
    } else {
      setDiscoveredAssets([]);
    }

    if (errors.length > 0) {
      setError(errors.join(" | "));
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    if (didInitFetchRef.current) return;
    didInitFetchRef.current = true;
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (!selectedKey) return;
    if (!mergedAssets.some((item) => makeAssetKey(item) === selectedKey)) {
      setSelectedKey(null);
    }
  }, [mergedAssets, selectedKey]);

  async function handleSave(id, payload) {
    await api.updateIpMetadata(id, payload);
    await fetchData();
  }

  async function handleDelete(id) {
    await api.deleteIpMetadata(id);
    setSelectedKey(null);
    await fetchData();
  }

  async function handleCreateNew(payload) {
    await api.createIpMetadata(payload);
    await fetchData();
  }

  async function handleImportAssets(items) {
    const result = await api.importIpMetadata(items);
    await fetchData();
    return result;
  }

  async function handleCreateGroup(payload) {
    await api.createNetworkGroup(payload);
    await fetchData();
  }

  async function handleUpdateGroup(id, payload) {
    await api.updateNetworkGroup(id, payload);
    await fetchData();
  }

  async function handleDeleteGroup(id) {
    await api.deleteNetworkGroup(id);
    await fetchData();
  }

  async function handleImportGroups(items) {
    const result = await api.importNetworkGroups(items);
    await fetchData();
    return result;
  }

  return (
    <div className="flex h-[calc(100vh-3.5rem)]">
      <HierarchySidebar
        groups={groups}
        onSelectGroup={setSelectedGroupFilter}
        selectedGroupId={selectedGroupFilter?.id}
      />

      <div className="flex-1 overflow-hidden p-3 flex flex-col gap-2">
        {error && (
          <div className="px-3 py-2 text-xs text-danger bg-red-50 border border-red-200 rounded-lg">
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex-1 flex items-center justify-center px-4">
            <div className="w-full max-w-lg rounded-xl border border-neutral-200 bg-white shadow-sm px-4 py-3">
              <div className="flex items-center gap-2 text-slate-600">
                <span className="inline-flex items-center justify-center rounded-full bg-primary/10 text-primary p-1">
                  <span className="material-symbols-outlined animate-spin" style={{ fontSize: 16 }}>
                    progress_activity
                  </span>
                </span>
                <span className="text-sm font-medium">Loading assets and topology data...</span>
              </div>
              <div className="mt-2 h-2 w-full rounded-full bg-neutral-100 overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300"
                  style={{
                    width: `${loadProgress.total > 0 ? Math.round((loadProgress.done / loadProgress.total) * 100) : 0}%`,
                  }}
                />
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                {loadProgress.done}/{loadProgress.total} data sources loaded
              </p>
            </div>
          </div>
        ) : (
          <div className="flex-1 min-h-0">
            <AssetTable
              metadata={mergedAssets}
              selectedId={selectedKey}
              onSelect={setSelectedKey}
            />
          </div>
        )}
      </div>

      <MetadataEditorSidebar
        asset={selected && selected.id != null ? selected : null}
        seedAsset={selected && selected.id == null ? selected : null}
        onClearSelection={() => setSelectedKey(null)}
        groups={groups}
        onSave={handleSave}
        onDelete={handleDelete}
        onCreateNew={handleCreateNew}
        onImportAssets={handleImportAssets}
        onCreateGroup={handleCreateGroup}
        onUpdateGroup={handleUpdateGroup}
        onDeleteGroup={handleDeleteGroup}
        onImportGroups={handleImportGroups}
      />
    </div>
  );
}
