import { getAuthHeaders } from "./auth";

export const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

function toErrorMessage(error, fallback) {
  if (error?.response?.message) {
    return error.response.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return fallback;
}

function extractApiErrorMessage(payload) {
  if (!payload) return "";
  if (typeof payload === "string") return payload;
  if (Array.isArray(payload)) {
    for (const item of payload) {
      const message = extractApiErrorMessage(item);
      if (message) return message;
    }
    return "";
  }
  if (typeof payload === "object") {
    for (const value of Object.values(payload)) {
      const message = extractApiErrorMessage(value);
      if (message) return message;
    }
  }
  return "";
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const authHeaders = getAuthHeaders();
  Object.entries(authHeaders).forEach(([key, value]) => {
    if (!headers.has(key)) {
      headers.set(key, value);
    }
  });

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    const message =
      payload?.detail ||
      payload?.message ||
      extractApiErrorMessage(payload) ||
      `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

export function extractResults(payload) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.results)) return payload.results;
  return [];
}

function withPagination(path, params = {}, defaultPageSize = 250) {
  const query = new URLSearchParams();
  query.set("page_size", String(params.page_size || defaultPageSize));
  if (params.page) {
    query.set("page", String(params.page));
  }
  return `${path}?${query.toString()}`;
}

export const api = {
  getHealth: () => request("/health/"),
  listFlowLogs: (params = {}) => {
    const query = new URLSearchParams();
    query.set("page_size", String(params.page_size || 100));
    if (params.page) query.set("page", String(params.page));
    if (params.srcaddr) query.set("srcaddr", params.srcaddr);
    if (params.dstaddr) query.set("dstaddr", params.dstaddr);
    if (params.action) query.set("action", params.action);
    if (params.protocol) query.set("protocol", String(params.protocol));
    if (params.since) query.set("since", params.since);
    if (params.until) query.set("until", params.until);
    if (params.advanced_filter) query.set("advanced_filter", params.advanced_filter);
    return request(`/flow-logs/?${query.toString()}`);
  },
  listCorrelatedFlows: (params = {}) => request(withPagination("/correlated-flows/", params, 250)),
  listIpMetadata: (params = {}) => request(withPagination("/ip-metadata/", params, 250)),
  createIpMetadata: (body) =>
    request("/ip-metadata/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  updateIpMetadata: (id, body) =>
    request(`/ip-metadata/${id}/`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  deleteIpMetadata: (id) =>
    request(`/ip-metadata/${id}/`, { method: "DELETE" }),
  importIpMetadata: (items) =>
    request("/metadata/import/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items })
    }),
  importNetworkGroups: (items) =>
    request("/maintenance/network-groups/import/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items })
    }),
  listNetworkGroups: (params = {}) => request(withPagination("/network-groups/", params, 250)),
  createNetworkGroup: (body) =>
    request("/network-groups/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  updateNetworkGroup: (id, body) =>
    request(`/network-groups/${id}/`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  deleteNetworkGroup: (id) =>
    request(`/network-groups/${id}/`, { method: "DELETE" }),
  uploadFlowLogs: (formData) =>
    request("/uploads/flow-logs/", {
      method: "POST",
      body: formData
    }),
  rebuildCorrelation: () =>
    request("/correlation/rebuild/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    }),
  validateAdvancedFlowFilter: (advancedFilter) =>
    request("/maintenance/flow-logs/validate-filter/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ advanced_filter: advancedFilter })
    }),
  listFlowLogImports: () => request("/maintenance/flow-logs/imports/"),
  purgeFlowLogs: (source) =>
    request("/maintenance/flow-logs/purge/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(source === undefined ? {} : { source })
    }),
  purgeAllNetworkGroups: () =>
    request("/maintenance/network-groups/purge/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    }),
  getMesh: () => request("/mesh/?limit=300"),
  getFirewallRecommendations: (minBytes = 0) =>
    request(`/firewall/recommendations/?min_bytes=${minBytes}`),
  searchEverything: (q, limit = 25) => {
    const query = new URLSearchParams();
    if (q) query.set("q", q);
    if (limit) query.set("limit", String(limit));
    return request(`/search/?${query.toString()}`);
  }
};

export { toErrorMessage };
