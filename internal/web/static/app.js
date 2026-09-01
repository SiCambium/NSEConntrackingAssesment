"use strict";

const REFRESH_STORAGE_KEY = "conntrack.refreshSeconds";
const state = { firewallId: null, firewalls: [], pollIntervals: [30], refreshTimer: null };

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function fmtInterval(seconds) {
  return seconds < 60 ? `${seconds}s` : `${Math.round(seconds / 60)} min`;
}

function badge(bucket) {
  const b = (bucket || "low").toLowerCase();
  return `<span class="badge ${b}">${b}</span>`;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const body = await res.text();
    let msg = body;
    try { msg = JSON.parse(body).error || body; } catch (e) { /* not JSON */ }
    throw new Error(msg);
  }
  return res.json();
}

// ---- Tabs ----
$all(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    $all(".tab-btn").forEach(b => b.classList.remove("active"));
    $all(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    $("#tab-" + btn.dataset.tab).classList.add("active");
    refreshActiveTab();
  });
});

function activeTab() {
  return $(".tab-btn.active").dataset.tab;
}

function refreshActiveTab() {
  const tab = activeTab();
  if (tab === "settings") { loadSettings(); return; }
  if (!state.firewallId) return;
  if (tab === "flows") loadFlows();
  else if (tab === "ports") loadPorts();
  else if (tab === "approved") loadApproved();
  else if (tab === "rules") loadRules();
}

// ---- Meta (poll interval choices, shared by the refresh picker and the Settings form) ----
async function loadMeta() {
  try {
    const meta = await api("/api/meta");
    state.pollIntervals = meta.poll_intervals_seconds || state.pollIntervals;
  } catch (e) { /* keep defaults */ }

  const opts = state.pollIntervals.map(s => `<option value="${s}">${fmtInterval(s)}</option>`).join("");
  $("#refresh-select").innerHTML = opts;
  const pollSelect = $("select[name=poll_interval_seconds]", $("#settings-form"));
  pollSelect.innerHTML = opts;
  pollSelect.value = state.pollIntervals.includes(30) ? 30 : state.pollIntervals[0];

  const saved = parseInt(localStorage.getItem(REFRESH_STORAGE_KEY), 10);
  const initial = state.pollIntervals.includes(saved) ? saved : 30;
  $("#refresh-select").value = initial;
  applyRefreshInterval(initial);
}

function applyRefreshInterval(seconds) {
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(() => { loadFirewalls(); refreshActiveTab(); }, seconds * 1000);
}

$("#refresh-select").addEventListener("change", e => {
  const seconds = parseInt(e.target.value, 10);
  localStorage.setItem(REFRESH_STORAGE_KEY, String(seconds));
  applyRefreshInterval(seconds);
});

// ---- Open in Browser (desktop app mode only — see cmd/conntrack-app) ----
if (typeof window.conntrackOpenInBrowser === "function") {
  const btn = $("#open-in-browser");
  btn.hidden = false;
  btn.addEventListener("click", () => window.conntrackOpenInBrowser());
}

// ---- Firewall picker ----
async function loadFirewalls() {
  state.firewalls = await api("/api/firewalls");
  const select = $("#firewall-select");
  select.innerHTML = state.firewalls.map(f => `<option value="${f.ID || f.id}">${f.Name || f.name} (${f.Host || f.host})</option>`).join("");
  if (state.firewalls.length && !state.firewallId) {
    state.firewallId = state.firewalls[0].ID || state.firewalls[0].id;
  }
  select.value = state.firewallId;
  updateFwStatus();
}

function updateFwStatus() {
  const fw = state.firewalls.find(f => (f.ID || f.id) === state.firewallId);
  const el = $("#fw-status");
  if (!fw) { el.textContent = ""; return; }
  const ok = fw.LastPollOK !== undefined ? fw.LastPollOK : fw.last_poll_ok;
  el.className = "status " + (ok ? "ok" : "fail");
  const usage = fw.ConntrackUsage ?? fw.conntrack_usage ?? 0;
  const limit = fw.ConntrackLimit ?? fw.conntrack_limit ?? 0;
  el.textContent = ok
    ? `polling OK · conntrack ${usage}/${limit}`
    : `poll failing: ${fw.LastPollError || fw.last_poll_error || "unknown error"}`;
}

$("#firewall-select").addEventListener("change", e => {
  state.firewallId = e.target.value;
  updateFwStatus();
  refreshActiveTab();
});

// ---- Flows ----
$("#flow-filters").addEventListener("submit", e => {
  e.preventDefault();
  loadFlows();
});

async function loadFlows() {
  const form = $("#flow-filters");
  const params = new URLSearchParams();
  new FormData(form).forEach((v, k) => {
    if (k === "open_only") { if (v) params.set(k, "1"); return; }
    if (v) params.set(k, v);
  });
  const data = await api(`/api/firewalls/${state.firewallId}/flows?` + params.toString());
  const tbody = $("#flows-table tbody");
  tbody.innerHTML = data.flows.map(f => `
    <tr>
      <td>${badge(f.RiskBucket)}</td>
      <td>${f.Protocol}</td>
      <td>${f.OriginSrc}:${f.SrcPort || ""}</td>
      <td>${f.OriginDst}:${f.DstPort || ""}</td>
      <td>${f.Direction || ""}</td>
      <td>${f.Application || ""}</td>
      <td>${f.TCPState || ""}</td>
      <td>${f.HostName || ""}</td>
      <td>${fmtBytes((f.TxBytes || 0) + (f.RxBytes || 0))}</td>
      <td>${fmtTime(f.FirstSeen)}</td>
      <td>${fmtTime(f.LastSeen)}</td>
      <td class="reasons-cell" title="${(f.RiskReasons || []).join('; ')}">${(f.RiskReasons || []).length ? "ⓘ" : ""}</td>
    </tr>
  `).join("");
  $("#flows-summary").textContent = `${data.flows.length} shown of ${data.total} matching`;
}

// ---- Ports & risk ----
async function loadPorts() {
  const rows = await api(`/api/firewalls/${state.firewallId}/ports`);
  const tbody = $("#ports-table tbody");
  tbody.innerHTML = rows.map(u => `
    <tr>
      <td>${badge(u.RiskBucket)}</td>
      <td>${u.Protocol}</td>
      <td>${u.DstPort || ""}</td>
      <td>${u.Application || ""}</td>
      <td>${u.SampleCount}</td>
      <td>${u.DistinctDstIPs}</td>
      <td>${fmtBytes(u.TotalBytes)}</td>
      <td>${fmtTime(u.FirstSeen)}</td>
      <td>${fmtTime(u.LastSeen)}</td>
      <td class="reasons-cell">${(u.RiskReasons || []).join('; ')}</td>
      <td>
        ${u.Approved
          ? `<button class="secondary" data-action="unapprove" data-protocol="${u.Protocol}" data-port="${u.DstPort}" data-app="${u.Application || ""}">Unapprove</button>`
          : `<button data-action="approve" data-protocol="${u.Protocol}" data-port="${u.DstPort}" data-app="${u.Application || ""}">Approve</button>`}
      </td>
    </tr>
  `).join("");

  $all("button[data-action]", tbody).forEach(btn => {
    btn.addEventListener("click", async () => {
      const { action, protocol, port, app } = btn.dataset;
      const body = { protocol, dst_port: parseInt(port, 10) || 0, application: app, approved_by: "web-ui" };
      await api(`/api/firewalls/${state.firewallId}/ports/${action}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      loadPorts();
    });
  });
}

// ---- Approved ----
async function loadApproved() {
  const rows = await api(`/api/firewalls/${state.firewallId}/approved`);
  const tbody = $("#approved-table tbody");
  tbody.innerHTML = rows.map(a => `
    <tr>
      <td>${a.Protocol}</td>
      <td>${a.DstPort || ""}</td>
      <td>${a.Application || ""}</td>
      <td>${a.Label || ""}</td>
      <td>${a.ApprovedBy || ""}</td>
      <td>${fmtTime(a.ApprovedAt)}</td>
      <td><button class="secondary" data-protocol="${a.Protocol}" data-port="${a.DstPort}" data-app="${a.Application || ""}">Unapprove</button></td>
    </tr>
  `).join("");

  $all("button", tbody).forEach(btn => {
    btn.addEventListener("click", async () => {
      const { protocol, port, app } = btn.dataset;
      const body = { protocol, dst_port: parseInt(port, 10) || 0, application: app };
      await api(`/api/firewalls/${state.firewallId}/ports/unapprove`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      loadApproved();
    });
  });
}

// ---- Rules preview ----
$("#rules-refresh").addEventListener("click", loadRules);

async function loadRules() {
  const params = new URLSearchParams();
  params.set("min_sample_count", $("#rules-min-samples").value || "3");
  if ($("#rules-include-low").checked) params.set("include_low_risk", "1");

  const data = await api(`/api/firewalls/${state.firewallId}/rules/preview?` + params.toString());
  $("#rules-caveat").textContent = data.caveat;
  const tbody = $("#rules-table tbody");
  tbody.innerHTML = (data.rules || []).map(r => `
    <tr>
      <td>${r.name}</td>
      <td>${r.rule_action}</td>
      <td>${r.protocol}</td>
      <td>${r.dst_port || ""}</td>
      <td>${r.precedence}</td>
      <td>${badge(r.risk_bucket)}</td>
      <td>${r.reason}</td>
      <td>${r.notes || ""}</td>
    </tr>
  `).join("");
}

// ---- Settings (add/edit/remove firewalls) ----
const settingsForm = $("#settings-form");

async function loadSettings() {
  const data = await api("/api/settings/firewalls");
  $("#settings-unavailable").hidden = data.writable;
  settingsForm.hidden = !data.writable;

  const tbody = $("#settings-table tbody");
  tbody.innerHTML = data.firewalls.map(fw => `
    <tr>
      <td><span class="status-dot ${fw.running ? "on" : "off"}"></span>${fw.running ? "polling" : "stopped"}</td>
      <td>${fw.name}</td>
      <td>${fw.host}</td>
      <td>${fw.port}</td>
      <td>${fw.user}</td>
      <td>${fmtInterval(fw.poll_interval_seconds)}</td>
      <td>
        <button class="secondary" data-action="edit" data-id="${fw.id}">Edit</button>
        <button class="secondary" data-action="remove" data-id="${fw.id}">Remove</button>
      </td>
    </tr>
  `).join("");

  $all("button[data-action=edit]", tbody).forEach(btn => {
    btn.addEventListener("click", () => {
      const fw = data.firewalls.find(f => f.id === btn.dataset.id);
      if (!fw) return;
      settingsForm.editing_id.value = fw.id;
      settingsForm.name.value = fw.name;
      settingsForm.host.value = fw.host;
      settingsForm.port.value = fw.port;
      settingsForm.user.value = fw.user;
      settingsForm.password.value = "";
      settingsForm.password.placeholder = "leave blank to keep the current password";
      settingsForm.password.required = false;
      settingsForm.poll_interval_seconds.value = fw.poll_interval_seconds;
      $("#settings-form-title").textContent = `Edit ${fw.name}`;
      $("#settings-cancel-edit").hidden = false;
      settingsForm.scrollIntoView({ behavior: "smooth" });
    });
  });

  $all("button[data-action=remove]", tbody).forEach(btn => {
    btn.addEventListener("click", async () => {
      const fw = data.firewalls.find(f => f.id === btn.dataset.id);
      if (!fw) return;
      if (!confirm(`Stop polling "${fw.name}"? Its history stays in the database — this only stops live polling.`)) return;
      await api(`/api/settings/firewalls/${fw.id}`, { method: "DELETE" });
      loadSettings();
      loadFirewalls();
    });
  });
}

function resetSettingsForm() {
  settingsForm.reset();
  settingsForm.editing_id.value = "";
  settingsForm.password.placeholder = "required";
  settingsForm.password.required = true;
  settingsForm.port.value = 22;
  $("#settings-form-title").textContent = "Add a firewall";
  $("#settings-cancel-edit").hidden = true;
  $("#settings-form-error").textContent = "";
}

$("#settings-cancel-edit").addEventListener("click", resetSettingsForm);

settingsForm.addEventListener("submit", async e => {
  e.preventDefault();
  $("#settings-form-error").textContent = "";
  const editingId = settingsForm.editing_id.value;
  const body = {
    name: settingsForm.name.value.trim(),
    host: settingsForm.host.value.trim(),
    port: parseInt(settingsForm.port.value, 10) || 22,
    user: settingsForm.user.value.trim(),
    password: settingsForm.password.value,
    poll_interval_seconds: parseInt(settingsForm.poll_interval_seconds.value, 10),
  };
  try {
    if (editingId) {
      await api(`/api/settings/firewalls/${editingId}`, {
        method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
    } else {
      await api("/api/settings/firewalls", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
    }
    resetSettingsForm();
    loadSettings();
    loadFirewalls();
  } catch (err) {
    $("#settings-form-error").textContent = err.message;
  }
});

// ---- Boot ----
(async function init() {
  await loadMeta();
  await loadFirewalls();
  refreshActiveTab();
})();
