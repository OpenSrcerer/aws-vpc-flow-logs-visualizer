import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import CytoscapeComponent from "react-cytoscapejs";
import Icon from "../Icon";
import {
  LAYOUT_PRESETS,
  buildGraphModel,
  buildStyles,
  formatBytes,
  formatInt,
} from "../../lib/graph";

cytoscape.use(fcose);

function addPeerAggregate(bucket, nodeData, edgeData) {
  const peerId = nodeData?.id;
  if (!peerId) return;

  if (!bucket.has(peerId)) {
    bucket.set(peerId, {
      id: peerId,
      label: nodeData.label || nodeData.ip || peerId,
      ip: nodeData.ip || "",
      role: nodeData.role || "mixed",
      flows: 0,
      bytes: 0,
      packets: 0,
      protocols: new Set(),
      ports: new Set(),
    });
  }

  const item = bucket.get(peerId);
  item.flows += Number(edgeData?.flows || 0);
  item.bytes += Number(edgeData?.trafficBytes || 0);
  item.packets += Number(edgeData?.trafficPackets || 0);

  const protocol = String(edgeData?.protocol || "").trim();
  if (protocol) item.protocols.add(protocol);

  const port = edgeData?.port;
  if (port != null && port !== "") item.ports.add(String(port));
}

function finalizePeerAggregates(bucket) {
  return [...bucket.values()]
    .map((item) => ({
      ...item,
      protocols: [...item.protocols].sort((a, b) => a.localeCompare(b)),
      ports: [...item.ports].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })),
    }))
    .sort((a, b) => b.bytes - a.bytes);
}

function buildNodeRelationshipLookup(mesh) {
  const nodes = mesh?.nodes || [];
  const edges = mesh?.edges || [];

  const nodeById = new Map();
  for (const node of nodes) {
    if (!node?.id) continue;
    nodeById.set(node.id, {
      id: node.id,
      label: node.label || node.ip || node.id,
      ip: node.ip || "",
      role: node.role || "mixed",
    });
  }

  const buckets = {};
  for (const nodeId of nodeById.keys()) {
    buckets[nodeId] = { consumers: new Map(), providers: new Map() };
  }

  for (const edge of edges) {
    const sourceId = edge?.source;
    const targetId = edge?.target;
    if (!sourceId || !targetId) continue;

    const sourceNode = nodeById.get(sourceId);
    const targetNode = nodeById.get(targetId);
    if (!sourceNode || !targetNode) continue;

    const normalizedEdge = {
      flows: edge.flows || 0,
      trafficBytes: edge.bytes || 0,
      trafficPackets: edge.packets || 0,
      protocol: edge.protocol_name || String(edge.protocol || ""),
      port: edge.port ?? "*",
    };

    addPeerAggregate(buckets[sourceId].providers, targetNode, normalizedEdge);
    addPeerAggregate(buckets[targetId].consumers, sourceNode, normalizedEdge);
  }

  const lookup = {};
  for (const [nodeId, nodeBuckets] of Object.entries(buckets)) {
    lookup[nodeId] = {
      consumers: finalizePeerAggregates(nodeBuckets.consumers),
      providers: finalizePeerAggregates(nodeBuckets.providers),
    };
  }

  return lookup;
}

function getNodeRelationships(relationshipLookup, nodeId) {
  return relationshipLookup[nodeId] || { consumers: [], providers: [] };
}

/* ------------------------------------------------------------------ */
/*  Floating detail card (appears on selection, top-right overlay)    */
/* ------------------------------------------------------------------ */

function DetailCard({ selected, onClose }) {
  if (!selected) return null;

  return (
    <div className="absolute top-3 right-3 z-20 w-80 max-h-[calc(100%-1.5rem)] bg-white rounded-xl border border-neutral-200 shadow-2xl overflow-hidden animate-fade-in flex flex-col">
      {/* Close button */}
      <button
        onClick={onClose}
        className="absolute top-2 right-2 p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-neutral-100 transition-colors z-10"
      >
        <Icon name="close" size={16} />
      </button>

      <div className="overflow-y-auto">
        {selected.type === "group" && <GroupCard data={selected.data} />}
        {selected.type === "node" && (
          <NodeCard data={selected.data} relationships={selected.relationships} />
        )}
        {selected.type === "edge" && <EdgeCard data={selected.data} />}
      </div>
    </div>
  );
}

function GroupCard({ data }) {
  return (
    <>
      <div className="px-4 pt-4 pb-3 bg-primary/5 border-b border-neutral-200">
        <div className="flex items-center gap-2 mb-1">
          <Icon name="cloud" size={14} className="text-primary" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-primary">
            VPC Container
          </span>
        </div>
        <h3 className="text-base font-bold text-slate-900 pr-6">{data.label}</h3>
      </div>
      <div className="px-4 py-3 text-xs text-slate-500">
        Click individual service nodes inside this group to inspect traffic details.
      </div>
    </>
  );
}

function NodeCard({ data: d, relationships }) {
  const roleMap = {
    consumer: { label: "Consumer", cls: "text-role-web", bg: "bg-role-web" },
    provider: { label: "Provider", cls: "text-role-db", bg: "bg-role-db" },
    mixed: { label: "Mixed", cls: "text-role-app", bg: "bg-role-app" },
  };
  const role = roleMap[d.role] || roleMap.mixed;
  const total = d.bytesIn + d.bytesOut;
  const outPct = total > 0 ? Math.round((d.bytesOut / total) * 100) : 50;
  const tagPairs = Object.entries(d.tags || {});
  const owner = d.accountOwner || d.owner || d.provider || "";
  const providers = relationships?.providers || [];
  const consumers = relationships?.consumers || [];

  return (
    <>
      <div className="px-4 pt-4 pb-3 bg-neutral-50 border-b border-neutral-200">
        <div className="flex items-center gap-2 mb-1">
          <span className={`size-2 rounded-full ${role.bg}`} />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            {role.label} Node
          </span>
        </div>
        <h3 className="text-base font-bold text-slate-900 pr-6">{d.label}</h3>
        <p className="text-xs text-slate-500 font-mono mt-0.5">{d.ip}</p>
      </div>
      <div className="px-4 py-3 space-y-2">
        {d.group && (
          <Row label="Group" value={d.group} />
        )}
        {owner && (
          <Row label="Owner" value={owner} />
        )}
        {d.provider && d.provider !== owner && <Row label="Provider" value={d.provider} />}
        <Row label="Kind" value={d.assetKind || "UNKNOWN"} />
        {d.instanceId && <Row label="Instance" value={d.instanceId} mono />}
        {d.interfaceId && <Row label="ENI" value={d.interfaceId} mono />}
        {d.instanceType && <Row label="Type" value={d.instanceType} />}
        {d.state && <Row label="State" value={d.state} />}
        {(d.region || d.availabilityZone) && (
          <Row
            label="Region/AZ"
            value={[d.region, d.availabilityZone].filter(Boolean).join(" / ")}
          />
        )}
        {tagPairs.length > 0 && (
          <div className="space-y-1">
            <div className="flex justify-between items-center text-xs">
              <span className="text-slate-500">Tags</span>
              <span className="text-[10px] text-slate-400">{formatInt(tagPairs.length)}</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {tagPairs.map(([key, tagValue]) => (
                <span
                  key={key}
                  className="inline-flex items-center rounded-md border border-neutral-200 bg-neutral-50 px-1.5 py-0.5 text-[10px] text-slate-600 font-mono"
                >
                  {tagValue ? `${key}=${tagValue}` : key}
                </span>
              ))}
            </div>
          </div>
        )}
        <div className="border-t border-neutral-100 my-1" />
        <Row label="Bytes Out" value={formatBytes(d.bytesOut)} mono />
        <Row label="Bytes In" value={formatBytes(d.bytesIn)} mono />
        <Row label="Pkts Out" value={formatInt(d.packetsOut)} mono />
        <Row label="Pkts In" value={formatInt(d.packetsIn)} mono />

        {/* Traffic bar */}
        <div className="pt-1">
          <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden flex">
            <div className="h-full bg-role-web rounded-full" style={{ width: `${outPct}%` }} />
            <div className="h-full bg-role-db rounded-full" style={{ width: `${100 - outPct}%` }} />
          </div>
          <div className="flex justify-between text-[9px] text-slate-400 mt-0.5">
            <span>Out {outPct}%</span>
            <span>In {100 - outPct}%</span>
          </div>
        </div>

        <div className="border-t border-neutral-100 my-1" />
        <PeerSection
          title="Consumers"
          peers={consumers}
          emptyText="No consumers observed for this node."
        />
        <PeerSection
          title="Providers"
          peers={providers}
          emptyText="No providers observed for this node."
        />
      </div>
    </>
  );
}

function PeerSection({ title, peers, emptyText }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{title}</span>
        <span className="text-[10px] text-slate-400">{formatInt(peers.length)}</span>
      </div>
      {peers.length === 0 ? (
        <p className="text-[11px] text-slate-400">{emptyText}</p>
      ) : (
        <div className="space-y-1.5 max-h-36 overflow-y-auto pr-0.5">
          {peers.map((peer) => (
            <div key={peer.id} className="rounded-md border border-neutral-200 bg-neutral-50 px-2 py-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-slate-800 truncate">{peer.label}</span>
                <span className="text-[10px] text-slate-500 font-mono shrink-0">{formatBytes(peer.bytes)}</span>
              </div>
              <p className="text-[10px] text-slate-500 font-mono truncate">{peer.ip}</p>
              <p className="text-[10px] text-slate-500">
                {formatInt(peer.flows)} flows · {formatInt(peer.packets)} packets
              </p>
              <p className="text-[10px] text-slate-500 break-words">
                Protocols: {peer.protocols.join(", ") || "-"} · Ports: {peer.ports.join(", ") || "-"}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function EdgeCard({ data: d }) {
  return (
    <>
      <div className="px-4 pt-4 pb-3 bg-neutral-50 border-b border-neutral-200">
        <div className="flex items-center gap-2 mb-1">
          <Icon name="sync_alt" size={14} className="text-primary" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Flow Edge
          </span>
        </div>
        <h3 className="text-sm font-bold text-slate-900 pr-6">
          {d.sourceLabel} → {d.targetLabel}
        </h3>
      </div>
      <div className="px-4 py-3 space-y-2">
        <Row label="Protocol" value={d.protocol} />
        <Row label="Port" value={d.port} mono />
        <div className="border-t border-neutral-100 my-1" />
        <Row label="Flows" value={formatInt(d.flows)} mono />
        <Row label="Bytes" value={formatBytes(d.trafficBytes)} mono />
        <Row label="Packets" value={formatInt(d.trafficPackets)} mono />
      </div>
    </>
  );
}

function Row({ label, value, mono }) {
  return (
    <div className="flex justify-between items-center text-xs">
      <span className="text-slate-500">{label}</span>
      <span className={`text-slate-800 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main panel — full-bleed Cytoscape canvas with overlays            */
/* ------------------------------------------------------------------ */

export default function TopologyPanel({ mesh }) {
  const [layoutName, setLayoutName] = useState("fcose");
  const [hideLowTraffic, setHideLowTraffic] = useState(true);
  const [selected, setSelected] = useState(null);

  const cyRef = useRef(null);
  const relationshipLookupRef = useRef({});

  const graph = useMemo(
    () =>
      buildGraphModel(mesh, {
        hideLowTrafficEdges: hideLowTraffic,
        nodeLimit: 120,
        edgeLimit: 400,
      }),
    [mesh, hideLowTraffic]
  );

  const layout = useMemo(
    () => LAYOUT_PRESETS[layoutName] || LAYOUT_PRESETS.cose,
    [layoutName]
  );

  const stylesheet = useMemo(
    () => buildStyles(graph.maxTraffic, graph.maxEdgeBytes),
    [graph.maxTraffic, graph.maxEdgeBytes]
  );
  const relationshipLookup = useMemo(() => buildNodeRelationshipLookup(mesh), [mesh]);

  useEffect(() => {
    relationshipLookupRef.current = relationshipLookup;
  }, [relationshipLookup]);

  useEffect(() => {
    setSelected((current) => {
      if (!current || current.type !== "node") return current;
      return {
        ...current,
        relationships: getNodeRelationships(relationshipLookup, current.data.id),
      };
    });
  }, [relationshipLookup]);

  function bindCy(cy) {
    cyRef.current = cy;

    // Rebind on each cy callback so interaction handlers survive graph remounts.
    cy.off("tap", "node");
    cy.off("tap", "edge");
    cy.off("tap");

    cy.on("tap", "node", (e) => {
      const d = e.target.data();
      if (d.isGroup) {
        setSelected({ type: "group", data: d });
        return;
      }
      setSelected({
        type: "node",
        data: d,
        relationships: getNodeRelationships(relationshipLookupRef.current, d.id),
      });
    });
    cy.on("tap", "edge", (e) => {
      setSelected({ type: "edge", data: e.target.data() });
    });
    cy.on("tap", (e) => {
      if (e.target === cy) setSelected(null);
    });
  }

  const hasData = graph.elements.length > 0;

  return (
    <div className="relative w-full h-full overflow-hidden bg-bg">
      {/* Grid background */}
      <div
        className="absolute inset-0 z-0 pointer-events-none opacity-[0.05]"
        style={{
          backgroundImage:
            "linear-gradient(#453b2a 1px, transparent 1px), linear-gradient(90deg, #453b2a 1px, transparent 1px)",
          backgroundSize: "60px 60px",
        }}
      />

      {/* Cytoscape canvas — full bleed */}
      {hasData ? (
        <CytoscapeComponent
          cy={bindCy}
          elements={graph.elements}
          layout={layout}
          stylesheet={stylesheet}
          className="cytoscape-canvas"
          style={{ width: "100%", height: "100%", position: "absolute", inset: 0, zIndex: 1 }}
          wheelSensitivity={0.18}
          boxSelectionEnabled={false}
        />
      ) : (
        <div className="absolute inset-0 flex items-center justify-center z-10">
          <div className="text-center">
            <Icon name="hub" size={48} className="text-slate-300 mx-auto mb-3" />
            <p className="text-sm text-slate-500">No topology data available.</p>
            <p className="text-xs text-slate-400 mt-1">Upload flow logs to generate the service map.</p>
          </div>
        </div>
      )}

      {/* ---- Overlays (all positioned absolutely over the canvas) ---- */}

      {/* Top-left: title + controls */}
      <div className="absolute top-3 left-3 z-10 flex flex-col gap-2 pointer-events-none">
        <div className="bg-white/95 backdrop-blur-md px-4 py-3 rounded-xl border border-neutral-200 shadow-lg pointer-events-auto">
          <h1 className="text-sm font-bold text-slate-900">Grouped Container Service Map</h1>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Pan, zoom and click nodes to inspect.{" "}
            <span className="text-primary font-medium">Dashed boxes = VPC groups.</span>
          </p>
        </div>

        <div className="flex gap-1.5 pointer-events-auto">
          <button
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.3)}
            className="bg-white text-slate-600 p-1.5 rounded-lg border border-neutral-200 shadow-sm hover:bg-neutral-50 transition-colors"
            title="Zoom in"
          >
            <Icon name="add" size={18} />
          </button>
          <button
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 0.75)}
            className="bg-white text-slate-600 p-1.5 rounded-lg border border-neutral-200 shadow-sm hover:bg-neutral-50 transition-colors"
            title="Zoom out"
          >
            <Icon name="remove" size={18} />
          </button>
          <button
            onClick={() => cyRef.current?.fit(undefined, 40)}
            className="bg-white text-slate-600 p-1.5 rounded-lg border border-neutral-200 shadow-sm hover:bg-neutral-50 transition-colors"
            title="Fit to screen"
          >
            <Icon name="center_focus_strong" size={18} />
          </button>

          <div className="w-px bg-slate-200 mx-0.5" />

          <select
            value={layoutName}
            onChange={(e) => setLayoutName(e.target.value)}
            className="bg-white border border-neutral-200 rounded-lg px-2 py-1 text-xs text-slate-700 shadow-sm focus:outline-none focus:ring-2 focus:ring-primary pointer-events-auto"
          >
            <option value="fcose">fCoSE (Recommended)</option>
            <option value="cose">CoSE</option>
            <option value="concentric">Concentric</option>
            <option value="breadthfirst">Breadthfirst</option>
            <option value="circle">Circle</option>
          </select>

          <button
            onClick={() => cyRef.current?.layout({ ...layout, randomize: true }).run()}
            className="bg-primary hover:bg-primary-dark text-white px-3 py-1.5 rounded-lg text-xs font-medium shadow-sm transition-colors pointer-events-auto flex items-center gap-1"
          >
            <Icon name="refresh" size={14} />
            Rerun
          </button>

          <label className="flex items-center gap-1.5 bg-white border border-neutral-200 rounded-lg px-2 py-1 text-xs text-slate-600 shadow-sm cursor-pointer select-none pointer-events-auto">
            <input
              type="checkbox"
              checked={hideLowTraffic}
              onChange={(e) => setHideLowTraffic(e.target.checked)}
              className="rounded border-neutral-300 accent-primary"
            />
            Hide low traffic
          </label>
        </div>
      </div>

      {/* Bottom-left: legend */}
      <div className="absolute bottom-3 left-3 z-10 pointer-events-none">
        <div className="bg-white/95 backdrop-blur-md px-3 py-2 rounded-lg border border-neutral-200 shadow-lg flex items-center gap-3 text-[11px] pointer-events-auto">
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-role-web" />
            <span className="text-slate-600">Consumer</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-role-db" />
            <span className="text-slate-600">Provider</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-role-app" />
            <span className="text-slate-600">Mixed</span>
          </div>
          <div className="w-px h-3 bg-slate-300" />
          <div className="flex items-center gap-1.5">
            <span className="inline-block size-3.5 rounded border-2 border-dashed border-primary/50 bg-primary/5" />
            <span className="text-slate-600">VPC Group</span>
          </div>
        </div>
      </div>

      {/* Bottom-right: stats */}
      <div className="absolute bottom-3 right-3 z-10 pointer-events-none">
        <div className="bg-white/95 backdrop-blur-md px-3 py-1.5 rounded-lg border border-neutral-200 shadow text-[11px] text-slate-500 pointer-events-auto">
          {formatInt(graph.renderedNodeCount)}/{formatInt(graph.allNodeCount)} nodes
          {" · "}
          {formatInt(graph.renderedEdgeCount)}/{formatInt(graph.allEdgeCount)} edges
          {graph.groupCount > 0 && (
            <>
              {" · "}
              <span className="text-primary font-medium">{graph.groupCount} groups</span>
            </>
          )}
        </div>
      </div>

      {/* Top-right: floating detail card (only when selected) */}
      <DetailCard selected={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
