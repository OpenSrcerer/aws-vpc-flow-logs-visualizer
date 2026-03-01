const AUTH_TOKEN_STORAGE_KEY = "vpc-auth-token";

export function setAuthSession(username, password) {
  const encoded = window.btoa(`${String(username || "")}:${String(password || "")}`);
  window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, encoded);
}

export function clearAuthSession() {
  window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
}

export function getAuthToken() {
  return window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY) || "";
}

export function getAuthHeaders() {
  const token = getAuthToken();
  if (!token) return {};
  return { Authorization: `Basic ${token}` };
}
