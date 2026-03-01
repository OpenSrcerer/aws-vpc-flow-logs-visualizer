export function formatBytes(value) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  );
  return `${(value / 1024 ** index).toFixed(2)} ${units[index]}`;
}

export function formatInt(value) {
  return new Intl.NumberFormat("en-US").format(value || 0);
}

export const LAYOUT_PRESETS = {
  fcose: {
    name: "fcose",
    fit: true,
    padding: 40,
    animate: true,
    animationDuration: 500,
    quality: "proof",
    randomize: true,
    nodeSeparation: 90,
    idealEdgeLength: 120,
    edgeElasticity: 0.45,
    nodeRepulsion: 6500,
    gravityRange: 3.8,
    gravity: 0.25,
    gravityCompound: 1.0,
    gravityRangeCompound: 1.5,
    numIter: 2500,
    tilingPaddingVertical: 20,
    tilingPaddingHorizontal: 20,
    nestingFactor: 0.1,
    packComponents: true,
    componentSpacing: 80,
  },
  cose: {
    name: "cose",
    fit: true,
    padding: 40,
    animate: true,
    animationDuration: 400,
    randomize: true,
    idealEdgeLength: 120,
    edgeElasticity: 80,
    nodeRepulsion: 8000,
    nestingFactor: 1.2,
  },
  concentric: {
    name: "concentric",
    fit: true,
    padding: 40,
    animate: true,
    animationDuration: 320,
    minNodeSpacing: 24,
    levelWidth: () => 1,
  },
  breadthfirst: {
    name: "breadthfirst",
    fit: true,
    padding: 40,
    animate: true,
    animationDuration: 320,
    directed: true,
    spacingFactor: 1.4,
  },
  circle: {
    name: "circle",
    fit: true,
    padding: 30,
    animate: true,
    animationDuration: 260,
  },
};

/**
 * Build a Cytoscape element model with compound (parent) nodes for groups.
 *
 * - Each unique `group` value becomes a parent node.
 * - Individual IP nodes get `parent: groupId` so Cytoscape draws them
 *   inside the group container.
 * - Edges are still individual client→server flows.
 */
export function buildGraphModel(
  mesh,
  { hideLowTrafficEdges, nodeLimit = 120, edgeLimit = 400 }
) {
  const allNodes = mesh?.nodes || [];
  const allEdges = mesh?.edges || [];

  // Sort by traffic, take top N
  const sortedNodes = [...allNodes].sort(
    (a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out)
  );
  const selectedNodes = sortedNodes.slice(0, nodeLimit);
  const allowedIds = new Set(selectedNodes.map((n) => n.id));

  // Filter & cap edges
  let filteredEdges = allEdges
    .filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, edgeLimit);

  const rawMaxEdgeBytes = filteredEdges[0]?.bytes || 0;
  if (hideLowTrafficEdges && rawMaxEdgeBytes > 0) {
    const threshold = rawMaxEdgeBytes * 0.04;
    filteredEdges = filteredEdges.filter(
      (e, i) => i < 40 || e.bytes >= threshold
    );
  }

  const maxTraffic = selectedNodes[0]
    ? selectedNodes[0].bytes_in + selectedNodes[0].bytes_out
    : 0;
  const maxEdgeBytes = filteredEdges[0]?.bytes || 0;

  // Collect unique groups → compound parent nodes
  const groupSet = new Set();
  for (const node of selectedNodes) {
    if (node.group) groupSet.add(node.group);
  }

  const groupElements = [...groupSet].map((g) => ({
    data: {
      id: `group:${g}`,
      label: g,
      isGroup: true,
    },
  }));

  // Child nodes — set parent if the node has a group
  const nodeElements = selectedNodes.map((node) => ({
    data: {
      id: node.id,
      parent: node.group ? `group:${node.group}` : undefined,
      label: node.label || node.ip,
      shortLabel: (node.label || node.ip).slice(0, 16),
      role: node.role || "consumer",
      group: node.group || "",
      provider: node.provider || "",
      accountOwner: node.account_owner || "",
      owner: node.account_owner || node.provider || "",
      assetKind: node.asset_kind || "UNKNOWN",
      instanceId: node.instance_id || "",
      interfaceId: node.interface_id || "",
      instanceType: node.instance_type || "",
      state: node.state || "",
      region: node.region || "",
      availabilityZone: node.availability_zone || "",
      tags: node.tags || {},
      ip: node.ip,
      bytesIn: node.bytes_in || 0,
      bytesOut: node.bytes_out || 0,
      packetsIn: node.packets_in || 0,
      packetsOut: node.packets_out || 0,
      traffic: (node.bytes_in || 0) + (node.bytes_out || 0),
    },
  }));

  // Edges — individual client→server flows
  const edgeElements = filteredEdges.map((edge, index) => ({
    data: {
      id: `${edge.source}|${edge.target}|${edge.protocol}|${edge.port ?? "*"}|${index}`,
      source: edge.source,
      target: edge.target,
      protocol: edge.protocol_name || String(edge.protocol),
      port: edge.port ?? "*",
      flows: edge.flows || 0,
      trafficBytes: edge.bytes || 0,
      trafficPackets: edge.packets || 0,
      label: `${edge.protocol_name || edge.protocol}:${edge.port ?? "*"}`,
      sourceLabel: edge.source_label || edge.source,
      targetLabel: edge.target_label || edge.target,
    },
  }));

  return {
    elements: [...groupElements, ...nodeElements, ...edgeElements],
    maxTraffic,
    maxEdgeBytes,
    allNodeCount: allNodes.length,
    allEdgeCount: allEdges.length,
    renderedNodeCount: selectedNodes.length,
    renderedEdgeCount: filteredEdges.length,
    groupCount: groupSet.size,
  };
}

/**
 * Cytoscape stylesheet — light-mode Stitch palette with compound groups.
 */
export function buildStyles(maxTraffic, maxEdgeBytes) {
  const mt = Math.max(maxTraffic, 1);
  const me = Math.max(maxEdgeBytes, 1);

  return [
    /* ---- Compound / group nodes ---- */
    {
      selector: "node[?isGroup]",
      style: {
        shape: "round-rectangle",
        "background-color": "transparent",
        "background-opacity": 0,
        "border-width": 2,
        "border-style": "dashed",
        "border-color": "rgba(234, 169, 23, 0.35)",
        "border-opacity": 1,
        padding: "14px",
        label: "data(label)",
        color: "#64584a",
        "font-size": "12px",
        "font-weight": "600",
        "font-family": "Inter, sans-serif",
        "text-valign": "top",
        "text-halign": "center",
        "text-margin-y": -4,
        "text-background-color": "#f8f7f6",
        "text-background-opacity": 0.9,
        "text-background-padding": "3px",
        "text-background-shape": "roundrectangle",
      },
    },

    /* ---- Child / leaf nodes ---- */
    {
      selector: "node[!isGroup]",
      style: {
        label: "data(shortLabel)",
        color: "#334155",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 5,
        "font-size": "10px",
        "font-family": "Inter, sans-serif",
        "text-max-width": "80px",
        "text-wrap": "ellipsis",
        width: `mapData(traffic, 1, ${mt}, 28, 72)`,
        height: `mapData(traffic, 1, ${mt}, 28, 72)`,
        "border-width": 2,
        "border-color": "#ffffff",
        /* consumer = web/green by default */
        "background-color": "#10b981",
        "shadow-blur": 6,
        "shadow-color": "rgba(0,0,0,0.1)",
        "shadow-offset-x": 0,
        "shadow-offset-y": 2,
        "shadow-opacity": 1,
      },
    },
    {
      selector: 'node[role = "provider"]',
      style: { "background-color": "#3b82f6" },
    },
    {
      selector: 'node[role = "mixed"]',
      style: { "background-color": "#8b5cf6" },
    },

    /* ---- Edges (individual flows) ---- */
    {
      selector: "edge",
      style: {
        width: `mapData(trafficBytes, 1, ${me}, 1, 8)`,
        "line-color": "rgba(234, 169, 23, 0.35)",
        "target-arrow-color": "rgba(234, 169, 23, 0.6)",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.8,
        "curve-style": "bezier",
        opacity: 0.75,
      },
    },

    /* ---- Selection highlight ---- */
    {
      selector: ":selected",
      style: {
        "border-color": "#eaa917",
        "border-width": 3,
        "line-color": "#eaa917",
        "target-arrow-color": "#eaa917",
        opacity: 1,
      },
    },
  ];
}
