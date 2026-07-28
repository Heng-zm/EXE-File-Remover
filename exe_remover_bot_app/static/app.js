import { api, initializeTelegram, telegramWebApp } from "./api.js";
import { normalizeLanguage, translator } from "./i18n.js";

const root = document.querySelector("#app");
const webApp = initializeTelegram();

const state = {
  lang: normalizeLanguage(webApp?.initDataUnsafe?.user?.language_code || "en"),
  bootstrap: null,
  groups: [],
  currentGroupId: null,
  group: null,
  policyData: null,
  tab: "overview",
  tabLoading: false,
  busy: false,
  incidents: null,
  incidentFilters: {
    query: "",
    status: "all",
    severity: "all",
    action: "all",
    sort: "newest",
    page: 1,
    page_size: 20,
  },
  formats: null,
  hashes: null,
  administration: null,
};

const TAB_DEFS = [
  ["overview", "◉", "overview"],
  ["policies", "⚙", "policies"],
  ["incidents", "⚠", "incidents"],
  ["formats", "▤", "formats"],
  ["trusted", "✓", "trustedFiles"],
  ["administration", "♟", "administration"],
];

function t(key, values) {
  return translator(state.lang)(key, values);
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function initials(name) {
  return String(name || "ER")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("") || "ER";
}

function formatDate(value) {
  if (!value) return "—";
  const date = typeof value === "number" ? new Date(value) : new Date(String(value));
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(state.lang === "km" ? "km-KH" : "en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return "0 MB";
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KB`;
  return `${(value / (1024 * 1024)).toFixed(value >= 100 * 1024 * 1024 ? 0 : 1)} MB`;
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function localizedSetting(value) {
  const map = {
    standard: t("standard"), high: t("high"), strict: t("strict"),
    off: t("off"), warn: t("warn"), smart: t("smart"), ban: t("ban"),
    scan: t("archiveScan"), block: t("block"), allow: t("allow"),
    group_and_admins: t("groupAndAdmins"), admins_only: t("adminsOnly"),
    group_only: t("groupOnly"), silent: t("silent"),
  };
  return map[value] || titleCase(value);
}

function currentUser() {
  return state.bootstrap?.user || state.bootstrap?.saved_profile || {};
}

function updateGroupSnapshot(group) {
  if (!group) return;
  state.group = group;
  state.currentGroupId = group.id;
  const index = state.groups.findIndex((item) => Number(item.id) === Number(group.id));
  if (index >= 0) state.groups[index] = group;
}

function showToast(message, type = "success", detail = "") {
  let stack = document.querySelector("#global-toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.id = "global-toast-stack";
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.innerHTML = `<strong>${esc(message)}</strong>${detail ? `<span>${esc(detail)}</span>` : ""}`;
  stack.appendChild(node);
  window.setTimeout(() => node.remove(), 4200);
}

function errorMessage(error) {
  return error instanceof Error ? error.message : t("unknownError");
}

function confirmDialog(message) {
  return new Promise((resolve) => {
    if (webApp?.showConfirm) {
      webApp.showConfirm(message, (confirmed) => resolve(Boolean(confirmed)));
      return;
    }
    resolve(window.confirm(message));
  });
}

function renderBoot() {
  root.innerHTML = `
    <main class="boot-screen">
      <div class="brand-mark" aria-hidden="true">ER</div>
      <div class="boot-copy">
        <strong>${esc(t("appName"))}</strong>
        <span>${esc(t("loading"))}</span>
      </div>
    </main>`;
}

function renderAuthState(data) {
  root.innerHTML = `
    <main class="auth-state">
      <section class="state-card">
        <div class="state-icon" aria-hidden="true">↗</div>
        <h1>${esc(t("openInTelegram"))}</h1>
        <p>${esc(t("openInTelegramHelp"))}</p>
        <div class="button-row" style="justify-content:center">
          <button class="button primary" id="auth-retry" type="button">${esc(t("retry"))}</button>
        </div>
        ${data?.reason ? `<p class="code muted">${esc(data.reason)}</p>` : ""}
      </section>
    </main>`;
  document.querySelector("#auth-retry")?.addEventListener("click", () => boot(true));
}

function renderFatal(error) {
  root.innerHTML = `
    <main class="error-state">
      <section class="state-card">
        <div class="state-icon text-danger" aria-hidden="true">!</div>
        <h1>${esc(t("errorTitle"))}</h1>
        <p>${esc(errorMessage(error))}</p>
        <button class="button primary" id="fatal-retry" type="button">${esc(t("retry"))}</button>
      </section>
    </main>`;
  document.querySelector("#fatal-retry")?.addEventListener("click", () => boot(true));
}

function renderEmptyGroups() {
  const user = currentUser();
  root.innerHTML = `
    <div class="app-shell">
      ${renderHeader(user)}
      <main class="empty-state">
        <section class="state-card">
          <div class="state-icon" aria-hidden="true">＋</div>
          <h1>${esc(t("noGroups"))}</h1>
          <p>${esc(t("noGroupsHelp"))}</p>
          <button class="button primary" id="empty-refresh" type="button">${esc(t("refresh"))}</button>
        </section>
      </main>
    </div>`;
  bindHeaderEvents();
  document.querySelector("#empty-refresh")?.addEventListener("click", () => boot(true));
}

function renderHeader(user) {
  const name = user.full_name || user.first_name || user.username || t("user");
  return `
    <header class="app-header">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">ER</div>
        <div class="brand-copy">
          <span class="brand-title">${esc(t("appName"))}</span>
          <span class="brand-subtitle">${esc(t("appSubtitle"))}</span>
        </div>
      </div>
      <div class="header-actions">
        <label class="hidden" for="language-select">${esc(t("language"))}</label>
        <select class="select" id="language-select" aria-label="${esc(t("language"))}" style="width:auto;min-height:38px;padding:6px 30px 6px 9px">
          <option value="en" ${state.lang === "en" ? "selected" : ""}>EN</option>
          <option value="km" ${state.lang === "km" ? "selected" : ""}>ខ្មែរ</option>
        </select>
        <button class="icon-button" id="global-refresh" type="button" title="${esc(t("refresh"))}" aria-label="${esc(t("refresh"))}">↻</button>
        <div class="user-chip" title="${esc(name)}">
          <div class="avatar" aria-hidden="true">${esc(initials(name))}</div>
          <span>${esc(name)}</span>
        </div>
      </div>
    </header>`;
}

function renderSidebar() {
  return `
    <aside class="sidebar">
      <section class="sidebar-section">
        <div class="section-eyebrow">${esc(t("protectedGroups"))}</div>
        <div class="group-list">
          ${state.groups.map((group) => {
            const active = Number(group.id) === Number(state.currentGroupId);
            const count = Number(group.counts?.open_incidents || 0);
            return `
              <button class="group-button ${active ? "active" : ""}" type="button" data-group-id="${esc(group.id)}">
                <span class="group-icon" aria-hidden="true">#</span>
                <span class="group-copy">
                  <strong>${esc(group.title || group.id)}</strong>
                  <span>${esc(group.protection_enabled ? t("enabled") : t("disabled"))}</span>
                </span>
                ${count ? `<span class="group-count">${count}</span>` : ""}
              </button>`;
          }).join("")}
        </div>
      </section>
    </aside>`;
}

function renderMobileGroupSelect() {
  return `
    <label class="mobile-group-select">
      <span class="form-label">${esc(t("protectedGroups"))}</span>
      <select class="select" id="mobile-group-select">
        ${state.groups.map((group) => `<option value="${esc(group.id)}" ${Number(group.id) === Number(state.currentGroupId) ? "selected" : ""}>${esc(group.title || group.id)}</option>`).join("")}
      </select>
    </label>`;
}

function renderGroupHero() {
  const group = state.group;
  const healthy = Boolean(group?.bot_permission?.can_delete_messages && group?.bot_permission?.settings_unlocked);
  return `
    ${renderMobileGroupSelect()}
    <section class="group-hero">
      <div>
        <h1>${esc(group?.title || group?.id || "")}</h1>
        <p><span class="code">${esc(group?.id || "")}</span> · ${esc(group?.type || "group")}</p>
      </div>
      <div class="button-row">
        <span class="health-badge ${healthy ? "good" : "warn"}">${healthy ? "●" : "▲"} ${esc(healthy ? t("protectionHealthy") : t("protectionNeedsPermission"))}</span>
        <button class="button small" id="group-refresh" type="button">↻ ${esc(t("refreshLive"))}</button>
      </div>
    </section>`;
}

function renderMetrics() {
  const group = state.group;
  const settings = group?.settings || {};
  const counts = group?.counts || {};
  const overview = state.bootstrap?.developer?.overview || {};
  return `
    <section class="metrics" aria-label="Dashboard metrics">
      <div class="metric-card"><span class="metric-label">${esc(t("protection"))}</span><strong class="metric-value">${esc(settings.protection_enabled ? t("enabled") : t("disabled"))}</strong><div class="metric-detail">${esc(localizedSetting(settings.strictness))}</div></div>
      <div class="metric-card"><span class="metric-label">${esc(t("openIncidents"))}</span><strong class="metric-value">${Number(counts.open_incidents || 0)}</strong><div class="metric-detail">${esc(t("incidents"))}</div></div>
      <div class="metric-card"><span class="metric-label">${esc(t("alertReady"))}</span><strong class="metric-value">${Number(counts.admin_alert_ready || 0)}/${Number(counts.admin_alert_total || 0)}</strong><div class="metric-detail">${esc(t("admins"))}</div></div>
      <div class="metric-card"><span class="metric-label">${esc(t("storage"))}</span><strong class="metric-value">${esc(overview.backend || "Connected")}</strong><div class="metric-detail">v3.5</div></div>
    </section>`;
}

function renderTabs() {
  return `
    <nav class="tabs" aria-label="Group dashboard sections">
      ${TAB_DEFS.map(([id, icon, key]) => `<button class="tab-button ${state.tab === id ? "active" : ""}" type="button" data-tab="${id}"><span aria-hidden="true">${icon}</span> ${esc(t(key))}</button>`).join("")}
    </nav>`;
}

function renderLoadingPanel() {
  return `<section class="panel"><div class="skeleton" style="width:34%;height:24px"></div><div class="skeleton" style="margin-top:16px;height:80px"></div><div class="skeleton" style="margin-top:10px;height:120px"></div></section>`;
}

function renderOverview() {
  const group = state.group;
  const settings = group.settings || {};
  const perms = group.bot_permission || {};
  return `
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("overview"))}</h2><p>${esc(t("appSubtitle"))}</p></div></div>
      <div class="panel-grid">
        <div class="info-list">
          <div class="info-row"><span>${esc(t("activePreset"))}</span><strong>${esc(titleCase(settings.scanner_preset || settings.detected_preset || "custom"))}</strong></div>
          <div class="info-row"><span>${esc(t("strictness"))}</span><strong>${esc(localizedSetting(settings.strictness))}</strong></div>
          <div class="info-row"><span>${esc(t("maxFileSize"))}</span><strong>${esc(formatBytes(settings.max_file_size_bytes))}</strong></div>
          <div class="info-row"><span>${esc(t("archivePolicy"))}</span><strong>${esc(localizedSetting(settings.archive_policy))}</strong></div>
        </div>
        <div class="info-list">
          <div class="info-row"><span>${esc(t("canDelete"))}</span><strong class="${perms.can_delete_messages ? "text-success" : "text-danger"}">${perms.can_delete_messages ? "✓" : "✕"}</strong></div>
          <div class="info-row"><span>${esc(t("canRestrict"))}</span><strong class="${perms.can_restrict_members ? "text-success" : "text-danger"}">${perms.can_restrict_members ? "✓" : "✕"}</strong></div>
          <div class="info-row"><span>${esc(t("permission"))}</span><strong>${esc(perms.status || "unknown")}</strong></div>
          <div class="info-row"><span>${esc(perms.settings_unlocked ? t("settingsUnlocked") : t("settingsLocked"))}</span><strong>${perms.settings_unlocked ? "✓" : "✕"}</strong></div>
        </div>
      </div>
    </section>
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("protection"))}</h2><p>${esc(t("saveChanges"))}</p></div></div>
      <form id="settings-form" class="form-grid">
        <label class="switch-row form-field full"><input type="checkbox" name="protection_enabled" ${settings.protection_enabled ? "checked" : ""}><span class="switch-copy"><strong>${esc(t("protection"))}</strong><span>${esc(settings.protection_enabled ? t("enabled") : t("disabled"))}</span></span></label>
        <label class="form-field"><span>${esc(t("strictness"))}</span><select class="select" name="strictness"><option value="standard" ${settings.strictness === "standard" ? "selected" : ""}>${esc(t("standard"))}</option><option value="high" ${settings.strictness === "high" ? "selected" : ""}>${esc(t("high"))}</option><option value="strict" ${settings.strictness === "strict" ? "selected" : ""}>${esc(t("strict"))}</option></select></label>
        <label class="form-field"><span>${esc(t("autoAction"))}</span><select class="select" name="auto_action_mode"><option value="off" ${settings.auto_action_mode === "off" ? "selected" : ""}>${esc(t("off"))}</option><option value="warn" ${settings.auto_action_mode === "warn" ? "selected" : ""}>${esc(t("warn"))}</option><option value="smart" ${settings.auto_action_mode === "smart" ? "selected" : ""}>${esc(t("smart"))}</option><option value="ban" ${settings.auto_action_mode === "ban" ? "selected" : ""}>${esc(t("ban"))}</option></select></label>
        <label class="switch-row form-field full"><input type="checkbox" name="silent_mode" ${settings.silent_mode ? "checked" : ""}><span class="switch-copy"><strong>${esc(t("silentMode"))}</strong><span>${esc(t("groupOnly"))}</span></span></label>
        <label class="switch-row form-field full"><input type="checkbox" name="strict_enforcement_on_admins" ${settings.strict_enforcement_on_admins ? "checked" : ""}><span class="switch-copy"><strong>${esc(t("enforceAdmins"))}</strong></span></label>
        <div class="form-field full"><button class="button primary" type="submit" ${state.busy ? "disabled" : ""}>${esc(state.busy ? t("saving") : t("saveChanges"))}</button></div>
      </form>
    </section>`;
}

function presetSummary(preset) {
  const settings = preset.settings || {};
  const parts = [];
  if (settings.strictness) parts.push(localizedSetting(settings.strictness));
  if (settings.allowed_only) parts.push(t("allowedOnly"));
  if (settings.archive_policy) parts.push(localizedSetting(settings.archive_policy));
  return parts.slice(0, 3);
}

function renderPolicies() {
  const data = state.policyData;
  if (!data) return renderLoadingPanel();
  const policy = data.policy || state.group.settings || {};
  const active = policy.scanner_preset || policy.detected_preset || "custom";
  return `
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("presetTitle"))}</h2><p>${esc(t("presetHelp"))}</p></div></div>
      <div class="preset-grid">
        ${(data.presets || []).map((preset) => `
          <article class="preset-card ${active === preset.id ? "active" : ""}">
            <div class="preset-top"><div><h3>${esc(preset.name)}</h3><p>${esc(preset.description)}</p></div>${active === preset.id ? `<span class="status-badge open">${esc(t("current"))}</span>` : ""}</div>
            <div class="preset-settings">${presetSummary(preset).map((item) => `<span class="mini-chip">${esc(item)}</span>`).join("")}</div>
            ${preset.id === "custom" ? "" : `<button class="button ${active === preset.id ? "ghost" : "primary"} small" type="button" data-preset="${esc(preset.id)}" ${state.busy || active === preset.id ? "disabled" : ""}>${esc(t("applyPreset"))}</button>`}
          </article>`).join("")}
      </div>
    </section>
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("customPolicies"))}</h2><p>${esc(t("maxFileSizeHelp"))}</p></div></div>
      <form id="policy-form" class="form-grid">
        <label class="switch-row form-field full"><input type="checkbox" name="allowed_only" ${policy.allowed_only ? "checked" : ""}><span class="switch-copy"><strong>${esc(t("allowedOnly"))}</strong></span></label>
        <label class="form-field"><span>${esc(t("maxFileSize"))} (${esc(t("mb"))})</span><input class="input" type="number" name="max_file_size_mb" min="0.1" max="2048" step="0.1" value="${esc((Number(policy.max_file_size_bytes || 0) / (1024 * 1024)).toFixed(1))}"><span class="form-help">${esc(t("maxFileSizeHelp"))}</span></label>
        <label class="form-field"><span>${esc(t("archivePolicy"))}</span><select class="select" name="archive_policy"><option value="scan" ${policy.archive_policy === "scan" ? "selected" : ""}>${esc(t("archiveScan"))}</option><option value="block" ${policy.archive_policy === "block" ? "selected" : ""}>${esc(t("archiveBlock"))}</option><option value="allow" ${policy.archive_policy === "allow" ? "selected" : ""}>${esc(t("archiveAllow"))}</option></select></label>
        <label class="form-field"><span>${esc(t("unscannablePolicy"))}</span><select class="select" name="unscannable_policy"><option value="block" ${policy.unscannable_policy === "block" ? "selected" : ""}>${esc(t("block"))}</option><option value="allow" ${policy.unscannable_policy === "allow" ? "selected" : ""}>${esc(t("allow"))}</option></select></label>
        <label class="form-field"><span>${esc(t("notificationPolicy"))}</span><select class="select" name="notification_policy"><option value="group_and_admins" ${policy.notification_policy === "group_and_admins" ? "selected" : ""}>${esc(t("groupAndAdmins"))}</option><option value="admins_only" ${policy.notification_policy === "admins_only" ? "selected" : ""}>${esc(t("adminsOnly"))}</option><option value="group_only" ${policy.notification_policy === "group_only" ? "selected" : ""}>${esc(t("groupOnly"))}</option><option value="silent" ${policy.notification_policy === "silent" ? "selected" : ""}>${esc(t("silent"))}</option></select></label>
        <label class="form-field"><span>${esc(t("retentionDays"))}</span><input class="input" type="number" name="incident_retention_days" min="1" max="3650" value="${esc(policy.incident_retention_days || 30)}"><span class="form-help">${esc(t("days"))}</span></label>
        <label class="form-field full"><span>${esc(t("policyNotes"))}</span><textarea class="textarea" name="policy_notes" maxlength="500" placeholder="${esc(t("policyNotesPlaceholder"))}">${esc(policy.policy_notes || "")}</textarea></label>
        <div class="form-field full"><button class="button primary" type="submit" ${state.busy ? "disabled" : ""}>${esc(state.busy ? t("saving") : t("saveChanges"))}</button></div>
      </form>
    </section>`;
}

function renderIncidentCard(incident) {
  const token = incident.action_token || incident.key;
  return `
    <article class="incident-card">
      <div class="incident-head">
        <div class="incident-title"><strong>${esc(incident.file_name || t("file"))}</strong><span>${esc(incident.sender_name || incident.sender_id)} · <span class="code">${esc(incident.sender_id)}</span></span></div>
        <div class="incident-badges"><span class="severity-badge ${esc(incident.severity)}">${esc(localizedSetting(incident.severity))}</span><span class="status-badge ${esc(incident.status)}">${esc(incident.status === "open" ? t("open") : t("handled"))}</span></div>
      </div>
      <div class="incident-meta">
        <div><span>${esc(t("created"))}</span><strong>${esc(formatDate(incident.created_at || incident.created_at_ms))}</strong></div>
        <div><span>${esc(t("action"))}</span><strong>${esc(localizedSetting(incident.effective_action || "none"))}</strong></div>
        <div><span>${esc(t("handledBy"))}</span><strong>${esc(incident.handled_by_name || "—")}</strong></div>
      </div>
      <p class="incident-reason">${esc(incident.reason || incident.reason_code || "")}</p>
      ${incident.status === "open" ? `<div class="incident-actions"><button class="button small" type="button" data-incident-action="warn" data-token="${esc(token)}">${esc(t("warn"))}</button><button class="button small danger" type="button" data-incident-action="ban" data-token="${esc(token)}">${esc(t("ban"))}</button><button class="button small ghost" type="button" data-incident-action="ignore" data-token="${esc(token)}">${esc(t("ignore"))}</button></div>` : ""}
    </article>`;
}

function renderIncidents() {
  const data = state.incidents;
  const filters = state.incidentFilters;
  return `
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("incidents"))}</h2><p>${esc(data ? t("totalResults", { count: data.total || 0 }) : t("loading"))}</p></div></div>
      <form id="incident-filter-form" class="filter-grid">
        <label class="form-field search-field"><span>${esc(t("incidentSearch"))}</span><input class="input" name="query" value="${esc(filters.query)}" placeholder="${esc(t("incidentSearchPlaceholder"))}"></label>
        <label class="form-field"><span>${esc(t("status"))}</span><select class="select" name="status"><option value="all" ${filters.status === "all" ? "selected" : ""}>${esc(t("all"))}</option><option value="open" ${filters.status === "open" ? "selected" : ""}>${esc(t("open"))}</option><option value="handled" ${filters.status === "handled" ? "selected" : ""}>${esc(t("handled"))}</option></select></label>
        <label class="form-field"><span>${esc(t("severity"))}</span><select class="select" name="severity"><option value="all" ${filters.severity === "all" ? "selected" : ""}>${esc(t("all"))}</option><option value="low" ${filters.severity === "low" ? "selected" : ""}>${esc(t("low"))}</option><option value="medium" ${filters.severity === "medium" ? "selected" : ""}>${esc(t("medium"))}</option><option value="high" ${filters.severity === "high" ? "selected" : ""}>${esc(t("high"))}</option><option value="critical" ${filters.severity === "critical" ? "selected" : ""}>${esc(t("critical"))}</option></select></label>
        <label class="form-field"><span>${esc(t("action"))}</span><select class="select" name="action"><option value="all" ${filters.action === "all" ? "selected" : ""}>${esc(t("all"))}</option><option value="none" ${filters.action === "none" ? "selected" : ""}>—</option><option value="warn" ${filters.action === "warn" ? "selected" : ""}>${esc(t("warn"))}</option><option value="ban" ${filters.action === "ban" ? "selected" : ""}>${esc(t("ban"))}</option><option value="ignore" ${filters.action === "ignore" ? "selected" : ""}>${esc(t("ignore"))}</option></select></label>
        <label class="form-field"><span>${esc(t("sort"))}</span><select class="select" name="sort"><option value="newest" ${filters.sort === "newest" ? "selected" : ""}>${esc(t("newest"))}</option><option value="oldest" ${filters.sort === "oldest" ? "selected" : ""}>${esc(t("oldest"))}</option></select></label>
        <div class="button-row"><button class="button primary small" type="submit">${esc(t("applyFilters"))}</button><button class="button ghost small" id="clear-incident-filters" type="button">${esc(t("clearFilters"))}</button></div>
      </form>
      ${state.tabLoading || !data ? renderLoadingPanel() : `
        <div class="incident-list">${data.incidents?.length ? data.incidents.map(renderIncidentCard).join("") : `<div class="empty-state" style="min-height:180px"><p class="muted">${esc(t("noIncidents"))}</p></div>`}</div>
        <div class="pagination"><button class="button small" id="incident-prev" type="button" ${!data.pagination?.has_previous ? "disabled" : ""}>← ${esc(t("previous"))}</button><div class="pagination-meta">${esc(t("pageOf", { page: data.pagination?.page || 1, pages: data.pagination?.pages || 1 }))}<br>${esc(t("totalResults", { count: data.total || 0 }))}</div><button class="button small" id="incident-next" type="button" ${!data.pagination?.has_next ? "disabled" : ""}>${esc(t("next"))} →</button></div>`}
    </section>`;
}

function extensionText(items) {
  return Array.isArray(items) ? items.join(" ") : "";
}

function renderFormats() {
  const data = state.formats;
  if (!data) return renderLoadingPanel();
  return `
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("formats"))}</h2><p>${esc(t("formatsHelp"))}</p></div></div>
      <form id="formats-form" class="form-grid">
        <label class="form-field full"><span>${esc(t("allowedFormats"))}</span><textarea class="textarea code" name="allowed">${esc(extensionText(data.allowed))}</textarea></label>
        <label class="form-field full"><span>${esc(t("blockedFormats"))}</span><textarea class="textarea code" name="blocked">${esc(extensionText(data.blocked))}</textarea></label>
        <div class="form-field full"><button class="button primary" type="submit" ${state.busy ? "disabled" : ""}>${esc(t("replaceFormats"))}</button></div>
      </form>
    </section>`;
}

function renderTrusted() {
  const data = state.hashes;
  if (!data) return renderLoadingPanel();
  const hashes = data.hashes || [];
  const metadata = data.metadata || {};
  return `
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("trustedHashes"))}</h2><p>${esc(t("trustedHelp"))}</p></div></div>
      <form id="hash-form" class="form-grid">
        <label class="form-field full"><span>SHA-256</span><input class="input code" name="sha256" minlength="64" maxlength="64" required placeholder="${esc(t("shaPlaceholder"))}"></label>
        <label class="form-field full"><span>${esc(t("fileNameOptional"))}</span><input class="input" name="file_name"></label>
        <div class="form-field full"><button class="button primary" type="submit" ${state.busy ? "disabled" : ""}>${esc(t("addHash"))}</button></div>
      </form>
    </section>
    <section class="panel">
      <div class="hash-list">
        ${hashes.length ? hashes.map((digest) => {
          const meta = metadata[digest] || {};
          return `<div class="list-row"><div class="list-main"><strong class="hash-code">${esc(digest)}</strong><span>${esc(meta.file_name || "")}</span></div><button class="button small danger" type="button" data-remove-hash="${esc(digest)}">${esc(t("remove"))}</button></div>`;
        }).join("") : `<p class="muted">${esc(t("noHashes"))}</p>`}
      </div>
    </section>`;
}

function renderAdministration() {
  const data = state.administration;
  if (!data) return renderLoadingPanel();
  return `
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("admins"))}</h2></div><button class="button small" id="admin-refresh" type="button">↻ ${esc(t("refreshLive"))}</button></div>
      <div class="admin-list">${data.admins.length ? data.admins.map((admin) => `<div class="list-row"><div class="list-main"><strong>${esc(admin.full_name || admin.id)}</strong><span>${admin.username ? `@${esc(admin.username)} · ` : ""}<span class="code">${esc(admin.id)}</span></span></div><span class="health-badge ${admin.alert_ready ? "good" : "warn"}">${esc(admin.alert_ready ? t("alertEnabled") : t("alertNotReady"))}</span></div>`).join("") : `<p class="muted">—</p>`}</div>
    </section>
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("riskUsers"))}</h2></div></div>
      <div class="risk-list">${data.risk.length ? data.risk.map((item) => `<div class="list-row"><div class="list-main"><strong>${esc(item.display_name || item.user_id)}</strong><span>${esc(t("incidentsCount"))}: ${Number(item.blocked || 0)} · ${esc(t("warnings"))}: ${Number(item.warned || 0)} · ${esc(t("bans"))}: ${Number(item.banned || 0)}</span></div><span class="severity-badge ${item.risk === "critical" ? "critical" : item.risk === "high" ? "high" : item.risk === "medium" ? "medium" : "low"}">${esc(titleCase(item.risk || "low"))}</span></div>`).join("") : `<p class="muted">${esc(t("noRiskUsers"))}</p>`}</div>
    </section>
    <section class="panel">
      <div class="panel-header"><div><h2>${esc(t("adminLogs"))}</h2></div></div>
      <div class="log-list">${data.logs.length ? data.logs.map((log) => `<div class="list-row"><div class="list-main"><strong>${esc(log.action || "Action")}</strong><span>${esc(log.admin_name || log.admin_id || "")} · ${esc(formatDate(log.created_at || log.created_at_ms))}</span><span>${esc(log.result || "")}</span></div></div>`).join("") : `<p class="muted">${esc(t("noAdminLogs"))}</p>`}</div>
    </section>`;
}

function renderTabContent() {
  if (state.tabLoading && !["incidents"].includes(state.tab)) return renderLoadingPanel();
  if (state.tab === "overview") return renderOverview();
  if (state.tab === "policies") return renderPolicies();
  if (state.tab === "incidents") return renderIncidents();
  if (state.tab === "formats") return renderFormats();
  if (state.tab === "trusted") return renderTrusted();
  if (state.tab === "administration") return renderAdministration();
  return "";
}

function renderDashboard() {
  if (!state.groups.length) {
    renderEmptyGroups();
    return;
  }
  const user = currentUser();
  root.innerHTML = `
    <div class="app-shell">
      ${renderHeader(user)}
      <div class="app-layout">
        ${renderSidebar()}
        <main class="content">
          ${renderGroupHero()}
          ${renderMetrics()}
          ${renderTabs()}
          <div id="tab-content">${renderTabContent()}</div>
        </main>
      </div>
      <div class="toast-stack" aria-live="polite"></div>
    </div>`;
  bindEvents();
}

function bindHeaderEvents() {
  document.querySelector("#global-refresh")?.addEventListener("click", () => refreshAll(true));
  document.querySelector("#language-select")?.addEventListener("change", async (event) => {
    const nextLang = normalizeLanguage(event.target.value);
    state.lang = nextLang;
    renderDashboard();
    try {
      await api.updatePreferences(nextLang);
      if (state.tab === "policies") await loadPolicyData();
    } catch (error) {
      showToast(t("errorTitle"), "error", errorMessage(error));
    }
  });
}

function bindEvents() {
  bindHeaderEvents();
  document.querySelector("#group-refresh")?.addEventListener("click", () => loadGroup(state.currentGroupId, true));
  document.querySelectorAll("[data-group-id]").forEach((button) => button.addEventListener("click", () => switchGroup(button.dataset.groupId)));
  document.querySelector("#mobile-group-select")?.addEventListener("change", (event) => switchGroup(event.target.value));
  document.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => switchTab(button.dataset.tab)));

  document.querySelector("#settings-form")?.addEventListener("submit", saveSettings);
  document.querySelector("#policy-form")?.addEventListener("submit", savePolicies);
  document.querySelectorAll("[data-preset]").forEach((button) => button.addEventListener("click", () => applyPreset(button.dataset.preset)));
  document.querySelector("#incident-filter-form")?.addEventListener("submit", applyIncidentFilters);
  document.querySelector("#clear-incident-filters")?.addEventListener("click", clearIncidentFilters);
  document.querySelector("#incident-prev")?.addEventListener("click", () => changeIncidentPage(-1));
  document.querySelector("#incident-next")?.addEventListener("click", () => changeIncidentPage(1));
  document.querySelectorAll("[data-incident-action]").forEach((button) => button.addEventListener("click", () => handleIncident(button.dataset.token, button.dataset.incidentAction)));
  document.querySelector("#formats-form")?.addEventListener("submit", saveFormats);
  document.querySelector("#hash-form")?.addEventListener("submit", addHash);
  document.querySelectorAll("[data-remove-hash]").forEach((button) => button.addEventListener("click", () => removeHash(button.dataset.removeHash)));
  document.querySelector("#admin-refresh")?.addEventListener("click", () => loadAdministration(true));
}

async function boot(refresh = false) {
  renderBoot();
  try {
    const data = await api.bootstrap(refresh);
    if (!data.authenticated && data.auth_required) {
      renderAuthState(data);
      return;
    }
    state.bootstrap = data;
    state.lang = normalizeLanguage(data.state?.lang || data.saved_profile?.lang || data.user?.language_code || state.lang);
    state.groups = Array.isArray(data.groups) ? data.groups : [];
    if (!state.groups.length) {
      renderEmptyGroups();
      return;
    }
    const existing = state.groups.find((group) => Number(group.id) === Number(state.currentGroupId));
    state.currentGroupId = existing?.id || state.groups[0].id;
    await loadGroup(state.currentGroupId, false, false);
    renderDashboard();
  } catch (error) {
    renderFatal(error);
  }
}

async function refreshAll(live = false) {
  try {
    state.busy = true;
    renderDashboard();
    const data = await api.bootstrap(live);
    state.bootstrap = data;
    state.groups = data.groups || [];
    await loadGroup(state.currentGroupId || state.groups[0]?.id, live, false);
    await loadCurrentTab(false);
    renderDashboard();
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.busy = false;
    renderDashboard();
  }
}

async function switchGroup(chatId) {
  if (Number(chatId) === Number(state.currentGroupId)) return;
  state.tab = "overview";
  state.policyData = null;
  state.incidents = null;
  state.formats = null;
  state.hashes = null;
  state.administration = null;
  await loadGroup(chatId, false);
}

async function loadGroup(chatId, refresh = false, rerender = true) {
  if (!chatId) return;
  state.currentGroupId = Number(chatId);
  state.tabLoading = true;
  if (rerender) renderDashboard();
  try {
    const result = await api.group(chatId, refresh);
    updateGroupSnapshot(result.group);
    state.policyData = null;
    state.incidents = null;
    state.formats = null;
    state.hashes = null;
    state.administration = null;
    await loadCurrentTab(false);
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.tabLoading = false;
    if (rerender) renderDashboard();
  }
}

async function switchTab(tab) {
  if (!TAB_DEFS.some(([id]) => id === tab)) return;
  state.tab = tab;
  state.tabLoading = true;
  renderDashboard();
  await loadCurrentTab(true);
}

async function loadCurrentTab(rerender = true) {
  try {
    if (state.tab === "policies") await loadPolicyData(false);
    else if (state.tab === "incidents") await loadIncidents(false);
    else if (state.tab === "formats") await loadFormats(false);
    else if (state.tab === "trusted") await loadHashes(false);
    else if (state.tab === "administration") await loadAdministration(false, false);
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.tabLoading = false;
    if (rerender) renderDashboard();
  }
}

async function loadPolicyData(rerender = true) {
  state.policyData = await api.policies(state.currentGroupId, state.lang);
  if (rerender) renderDashboard();
}

async function loadIncidents(rerender = true) {
  state.incidents = await api.incidents(state.currentGroupId, state.incidentFilters);
  if (rerender) renderDashboard();
}

async function loadFormats(rerender = true) {
  const [allowed, blocked] = await Promise.all([
    api.formats(state.currentGroupId, "allowed"),
    api.formats(state.currentGroupId, "blocked"),
  ]);
  state.formats = { allowed: allowed.extensions || [], blocked: blocked.extensions || [] };
  if (rerender) renderDashboard();
}

async function loadHashes(rerender = true) {
  state.hashes = await api.hashes(state.currentGroupId);
  if (rerender) renderDashboard();
}

async function loadAdministration(refresh = false, rerender = true) {
  state.tabLoading = true;
  if (rerender) renderDashboard();
  try {
    const [admins, logs, risk] = await Promise.all([
      api.admins(state.currentGroupId, refresh),
      api.adminLogs(state.currentGroupId, 50),
      api.risk(state.currentGroupId, 30),
    ]);
    state.administration = { admins: admins.admins || [], logs: logs.logs || [], risk: risk.risk || [] };
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.tabLoading = false;
    if (rerender) renderDashboard();
  }
}


async function saveSettings(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    protection_enabled: form.get("protection_enabled") === "on",
    strictness: form.get("strictness"),
    auto_action_mode: form.get("auto_action_mode"),
    silent_mode: form.get("silent_mode") === "on",
    strict_enforcement_on_admins: form.get("strict_enforcement_on_admins") === "on",
  };
  state.busy = true;
  renderDashboard();
  try {
    const result = await api.updateSettings(state.currentGroupId, payload);
    updateGroupSnapshot(result.group);
    state.policyData = null;
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.busy = false;
    renderDashboard();
  }
}

async function savePolicies(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    allowed_only: form.get("allowed_only") === "on",
    max_file_size_mb: Number(form.get("max_file_size_mb")),
    archive_policy: form.get("archive_policy"),
    unscannable_policy: form.get("unscannable_policy"),
    notification_policy: form.get("notification_policy"),
    incident_retention_days: Number(form.get("incident_retention_days")),
    policy_notes: form.get("policy_notes"),
  };
  state.busy = true;
  renderDashboard();
  try {
    const result = await api.updatePolicies(state.currentGroupId, payload);
    updateGroupSnapshot(result.group);
    await loadPolicyData(false);
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.busy = false;
    renderDashboard();
  }
}

async function applyPreset(presetId) {
  const preset = state.policyData?.presets?.find((item) => item.id === presetId);
  const confirmed = await confirmDialog(t("confirmPreset", { name: preset?.name || titleCase(presetId) }));
  if (!confirmed) return;
  state.busy = true;
  renderDashboard();
  try {
    const result = await api.applyPreset(state.currentGroupId, presetId);
    updateGroupSnapshot(result.group);
    await loadPolicyData(false);
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.busy = false;
    renderDashboard();
  }
}

function applyIncidentFilters(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  state.incidentFilters = {
    ...state.incidentFilters,
    query: String(form.get("query") || "").trim(),
    status: form.get("status"),
    severity: form.get("severity"),
    action: form.get("action"),
    sort: form.get("sort"),
    page: 1,
  };
  state.tabLoading = true;
  renderDashboard();
  loadIncidents(false)
    .catch((error) => showToast(t("errorTitle"), "error", errorMessage(error)))
    .finally(() => { state.tabLoading = false; renderDashboard(); });
}

function clearIncidentFilters() {
  state.incidentFilters = { query: "", status: "all", severity: "all", action: "all", sort: "newest", page: 1, page_size: 20 };
  state.tabLoading = true;
  renderDashboard();
  loadIncidents(false)
    .catch((error) => showToast(t("errorTitle"), "error", errorMessage(error)))
    .finally(() => { state.tabLoading = false; renderDashboard(); });
}

function changeIncidentPage(delta) {
  const current = Number(state.incidents?.pagination?.page || 1);
  state.incidentFilters.page = Math.max(1, current + delta);
  state.tabLoading = true;
  renderDashboard();
  loadIncidents(false)
    .catch((error) => showToast(t("errorTitle"), "error", errorMessage(error)))
    .finally(() => { state.tabLoading = false; renderDashboard(); });
}

async function handleIncident(token, action) {
  const confirmed = await confirmDialog(t("confirmAction", { action: localizedSetting(action) }));
  if (!confirmed) return;
  try {
    await api.incidentAction(token, action);
    await Promise.all([loadIncidents(false), api.group(state.currentGroupId).then((result) => updateGroupSnapshot(result.group))]);
    renderDashboard();
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  }
}

function parseExtensions(value) {
  return String(value || "").split(/[\s,;|]+/).map((item) => item.trim()).filter(Boolean);
}

async function saveFormats(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  state.busy = true;
  renderDashboard();
  try {
    const [allowed, blocked] = await Promise.all([
      api.updateFormats(state.currentGroupId, "allowed", parseExtensions(form.get("allowed")), "replace"),
      api.updateFormats(state.currentGroupId, "blocked", parseExtensions(form.get("blocked")), "replace"),
    ]);
    state.formats = { allowed: allowed.extensions || [], blocked: blocked.extensions || [] };
    updateGroupSnapshot(blocked.group || allowed.group || state.group);
    state.policyData = null;
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  } finally {
    state.busy = false;
    renderDashboard();
  }
}

async function addHash(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const digest = String(form.get("sha256") || "").trim().toLowerCase();
  const fileName = String(form.get("file_name") || "").trim();
  if (!/^[a-f0-9]{64}$/.test(digest)) {
    showToast(t("errorTitle"), "error", t("shaPlaceholder"));
    return;
  }
  try {
    await api.addHash(state.currentGroupId, digest, fileName);
    await loadHashes(false);
    renderDashboard();
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  }
}

async function removeHash(digest) {
  const confirmed = await confirmDialog(t("confirmRemoveHash"));
  if (!confirmed) return;
  try {
    await api.deleteHash(state.currentGroupId, digest);
    await loadHashes(false);
    renderDashboard();
    showToast(t("saved"));
  } catch (error) {
    showToast(t("errorTitle"), "error", errorMessage(error));
  }
}

boot();
