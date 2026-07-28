const configuredPrefix = String(window.__EXE_REMOVER_CONFIG__?.apiPrefix || "/api").trim();
const API_PREFIX = `/${configuredPrefix.replace(/^\/+|\/+$/g, "") || "api"}`;

function apiPath(path) {
  const suffix = String(path || "");
  return `${API_PREFIX}${suffix.startsWith("/") ? suffix : `/${suffix}`}`;
}

export function telegramWebApp() {
  return window.Telegram?.WebApp || null;
}

export function getInitData() {
  return telegramWebApp()?.initData || "";
}

export function initializeTelegram() {
  const webApp = telegramWebApp();
  if (!webApp) return null;
  try {
    webApp.ready();
    webApp.expand();
    webApp.enableClosingConfirmation?.();
  } catch (_) {
    // The dashboard also supports a safe browser preview state.
  }
  return webApp;
}

function normalizeError(data, status) {
  const detail = data?.detail || data?.message || data?.error;
  return detail ? String(detail) : `Request failed (${status})`;
}

export async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const initData = getInitData();
  if (initData) headers.set("X-Telegram-Init-Data", initData);
  if (options.body != null && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data?.ok === false) {
    const error = new Error(normalizeError(data, response.status));
    error.status = response.status;
    error.payload = data;
    throw error;
  }
  return data;
}

export const api = {
  bootstrap(refresh = false) {
    return apiFetch(apiPath(`/bootstrap${refresh ? "?refresh=true" : ""}`), {
      method: "POST",
      body: "{}",
    });
  },
  group(chatId, refresh = false) {
    return apiFetch(apiPath(`/groups/${chatId}${refresh ? "?refresh=true" : ""}`));
  },
  updateSettings(chatId, payload) {
    return apiFetch(apiPath(`/groups/${chatId}/settings`), {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },
  policies(chatId, lang) {
    return apiFetch(apiPath(`/groups/${chatId}/policies?lang=${encodeURIComponent(lang)}`));
  },
  updatePolicies(chatId, payload) {
    return apiFetch(apiPath(`/groups/${chatId}/policies`), {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },
  applyPreset(chatId, presetId) {
    return apiFetch(apiPath(`/groups/${chatId}/presets/${encodeURIComponent(presetId)}`), {
      method: "POST",
      body: "{}",
    });
  },
  incidents(chatId, params = {}) {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
    });
    return apiFetch(apiPath(`/groups/${chatId}/incidents?${query.toString()}`));
  },
  incidentAction(tokenOrKey, action) {
    return apiFetch(apiPath(`/incidents/${encodeURIComponent(tokenOrKey)}/action`), {
      method: "POST",
      body: JSON.stringify({ action }),
    });
  },
  formats(chatId, kind) {
    return apiFetch(apiPath(`/groups/${chatId}/formats/${kind}`));
  },
  updateFormats(chatId, kind, extensions, mode = "replace") {
    return apiFetch(apiPath(`/groups/${chatId}/formats/${kind}`), {
      method: "POST",
      body: JSON.stringify({ mode, extensions }),
    });
  },
  hashes(chatId) {
    return apiFetch(apiPath(`/groups/${chatId}/trusted-hashes`));
  },
  addHash(chatId, sha256, fileName = "") {
    return apiFetch(apiPath(`/groups/${chatId}/trusted-hashes`), {
      method: "POST",
      body: JSON.stringify({ sha256, file_name: fileName }),
    });
  },
  deleteHash(chatId, digest) {
    return apiFetch(apiPath(`/groups/${chatId}/trusted-hashes/${encodeURIComponent(digest)}`), {
      method: "DELETE",
    });
  },
  admins(chatId, refresh = false) {
    return apiFetch(apiPath(`/groups/${chatId}/admins${refresh ? "?refresh=true" : ""}`));
  },
  adminLogs(chatId, limit = 50) {
    return apiFetch(apiPath(`/groups/${chatId}/admin-logs?limit=${limit}`));
  },
  risk(chatId, limit = 20) {
    return apiFetch(apiPath(`/groups/${chatId}/risk?limit=${limit}`));
  },
  updatePreferences(lang) {
    return apiFetch(apiPath(`/me/preferences`), {
      method: "PATCH",
      body: JSON.stringify({ lang }),
    });
  },
};
