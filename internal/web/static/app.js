"use strict";

const REFRESH_STORAGE_KEY = "conntrack.refreshSeconds";
const state = {
  firewallId: null, firewalls: [], pollIntervals: [30], refreshTimer: null,
  sourcesEnabled: false, rawFlows: [], portRows: [],
  sort: { flows: { key: null, dir: 1 }, ports: { key: null, dir: 1 } },
};

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

function approvedBadge(approved) {
  return approved ? `<span class="badge approved">approved</span>` : `<span class="badge not-approved">no</span>`;
}

// Risk is always shown two ways: the badge is the COMBINED score; this
// renders the INDIVIDUAL contributing factors, each with its own point
// value, so you can see what actually made up that number.
function reasonLine(r) {
  const sign = r.points >= 0 ? "+" : "";
  return `${sign}${r.points} ${r.description}`;
}
function reasonsTitle(reasons) {
  return (reasons || []).map(reasonLine).join("\n");
}
function reasonsList(reasons) {
  if (!reasons || !reasons.length) return "";
  return `<ul class="reasons-list">${reasons.map(r => `<li>${reasonLine(r)}</li>`).join("")}</ul>`;
}

// Well-known port -> friendly service name, independent of the device's
// own DPI "Application" tag (which names the app — "chatgpt", "outlook",
// "grammarly" — not the protocol). Deliberately small: common ports only.
const WELL_KNOWN_PORTS = {
  20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
  67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
  123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 443: "HTTPS",
  465: "SMTPS", 500: "IKE/VPN", 514: "SYSLOG", 587: "SMTP", 993: "IMAPS",
  995: "POP3S", 1723: "PPTP", 3389: "RDP", 3478: "STUN/TURN", 4500: "IPSEC-NAT",
  5222: "XMPP", 5223: "APNS", 5228: "GCM/FCM", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
};
function portService(port) {
  return WELL_KNOWN_PORTS[Number(port)] || "";
}

// Row color-coding by destination port category — a different visual
// channel from the risk badge (border, not fill/text color), so the two
// signals never fight for the same color.
const PORT_CATEGORIES = [
  { name: "dns", cls: "cat-dns", ports: [53] },
  { name: "web", cls: "cat-web", ports: [80, 443, 8080, 8443] },
  { name: "mail", cls: "cat-mail", ports: [25, 110, 143, 465, 587, 993, 995] },
  { name: "admin", cls: "cat-admin", ports: [22, 23, 3389, 512, 513, 514] },
  { name: "vpn", cls: "cat-vpn", ports: [500, 1723, 4500] },
  { name: "realtime", cls: "cat-realtime", ports: [3478, 5222, 5223, 5228] },
];
function portCategoryClass(port) {
  const p = Number(port);
  const cat = PORT_CATEGORIES.find(c => c.ports.includes(p));
  return cat ? cat.cls : "";
}

// ---- Detail modal: click a risk badge to see everything about that row ----
const detailModal = $("#detail-modal");
$("#detail-close").addEventListener("click", () => detailModal.close());
detailModal.addEventListener("click", e => { if (e.target === detailModal) detailModal.close(); });

function openDetailModal(title, bodyHTML) {
  $("#detail-title").textContent = title;
  $("#detail-body").innerHTML = bodyHTML;
  wireIPLookupClicks($("#detail-body"));
  detailModal.showModal();
}

function riskBadgeButton(bucket) {
  return `<button class="risk-badge-btn">${badge(bucket)}</button>`;
}

function riskBreakdownHTML(score, bucket, reasons) {
  const body = (reasons && reasons.length) ? reasonsList(reasons) : `<p class="hint">No risk factors identified — nothing pushed this above baseline.</p>`;
  return `<h4>Risk: ${score} (${bucket})</h4>${body}`;
}

function lookupSectionHTML(ip) {
  if (!ip) return "";
  if (!state.sourcesEnabled) return `<h4>Destination lookup</h4><p class="hint">Turn on a data source in Settings to look up ${ip}.</p>`;
  return `<h4>Destination lookup</h4><div><button class="ip-link" data-ip="${ip}">Look up ${ip}</button><span class="lookup-results" data-ip-result="${ip}"></span></div>`;
}

function flowDetailHTML(f) {
  const dl = `<dl class="detail-dl">
    <dt>Protocol</dt><dd>${f.Protocol}</dd>
    <dt>Source</dt><dd>${f.OriginSrc}${f.SrcPort ? ":" + f.SrcPort : ""}</dd>
    <dt>Destination</dt><dd>${f.OriginDst}${f.DstPort ? ":" + f.DstPort : ""}</dd>
    <dt>Service</dt><dd>${portService(f.DstPort) || "—"}</dd>
    <dt>Direction</dt><dd>${f.Direction || "—"}</dd>
    <dt>Application</dt><dd>${f.Application || "—"}</dd>
    <dt>TCP state</dt><dd>${f.TCPState || "—"}</dd>
    <dt>Host name</dt><dd>${f.HostName || "—"}</dd>
    <dt>NAT'd to</dt><dd>${f.NatedIP ? f.NatedIP + (f.NatedPort ? ":" + f.NatedPort : "") : "—"}</dd>
    <dt>Bytes tx / rx</dt><dd>${fmtBytes(f.TxBytes)} / ${fmtBytes(f.RxBytes)}</dd>
    <dt>Packets tx / rx</dt><dd>${f.TxPackets ?? 0} / ${f.RxPackets ?? 0}</dd>
    <dt>First seen</dt><dd>${fmtTime(f.FirstSeen)}</dd>
    <dt>Last seen</dt><dd>${fmtTime(f.LastSeen)}</dd>
    <dt>Samples</dt><dd>${f.SampleCount ?? "—"}</dd>
    <dt>Status</dt><dd>${f.ClosedAt ? "closed " + fmtTime(f.ClosedAt) : "open"}</dd>
    <dt>Approved</dt><dd>${approvedBadge(f.Approved)}</dd>
  </dl>`;
  return dl + riskBreakdownHTML(f.RiskScore, f.RiskBucket, f.RiskReasons) + lookupSectionHTML(f.OriginDst);
}

function portDetailHTML(u) {
  const dl = `<dl class="detail-dl">
    <dt>Protocol</dt><dd>${u.Protocol}</dd>
    <dt>Port</dt><dd>${u.DstPort || "—"}</dd>
    <dt>Service</dt><dd>${portService(u.DstPort) || "—"}</dd>
    <dt>Application</dt><dd>${u.Application || "—"}</dd>
    <dt>Samples</dt><dd>${u.SampleCount}</dd>
    <dt>Distinct dst IPs</dt><dd>${u.DistinctDstIPs}</dd>
    <dt>Total bytes</dt><dd>${fmtBytes(u.TotalBytes)}</dd>
    <dt>First seen</dt><dd>${fmtTime(u.FirstSeen)}</dd>
    <dt>Last seen</dt><dd>${fmtTime(u.LastSeen)}</dd>
    <dt>Approved</dt><dd>${approvedBadge(u.Approved)}</dd>
  </dl>`;
  return dl + riskBreakdownHTML(u.RiskScore, u.RiskBucket, u.RiskReasons) +
    `<h4>Connections in this bucket</h4><div id="bucket-connections" class="hint">Loading…</div>`;
}

// loadBucketConnections fills in the "Connections in this bucket" section
// of the port detail modal asynchronously — it needs a request of its
// own (SessionsForBucket), so the modal opens immediately with a loading
// placeholder rather than waiting on it.
async function loadBucketConnections(u) {
  const container = $("#bucket-connections");
  if (!container) return;
  try {
    const params = new URLSearchParams({ protocol: u.Protocol, dst_port: u.DstPort || 0, application: u.Application || "" });
    const data = await api(`/api/firewalls/${state.firewallId}/ports/connections?` + params.toString());
    const sessions = data.sessions || [];
    if (!sessions.length) {
      container.innerHTML = `<p class="hint">No individual connections on record for this bucket.</p>`;
      return;
    }
    const shownNote = data.total > sessions.length ? ` (showing ${sessions.length} of ${data.total}, most recent first)` : "";
    container.innerHTML = `<p class="hint">${sessions.length} connection(s)${shownNote}:</p>
      <ul class="connections-list">${sessions.map(f => `
        <li>${ipCell(f.OriginSrc, f.SrcPort)} → ${ipCell(f.OriginDst, f.DstPort)}
          <span class="hint">· ${f.TCPState || f.Direction || "—"} · ${fmtBytes((f.TxBytes || 0) + (f.RxBytes || 0))} · last seen ${fmtTime(f.LastSeen)}${f.ClosedAt ? " · closed" : ""}</span>
        </li>`).join("")}</ul>`;
    wireIPLookupClicks(container);
  } catch (err) {
    container.innerHTML = `<p class="hint">Couldn't load connections: ${err.message}</p>`;
  }
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
  if (tab === "about") return;
  if (tab === "settings") { loadSettings(); return; }
  if (!state.firewallId) return;
  if (tab === "flows") loadFlows();
  else if (tab === "ports") loadPorts();
  else if (tab === "approved") loadApproved();
  else if (tab === "rules") loadRules();
}

// ---- Generic sortable-table helper ----
// Wires click handlers on every th[data-sort] inside `table`, keyed into
// state.sort[stateKey]. `render(rows)` re-renders from the currently held
// row array whenever the sort changes — callers supply accessors mapping
// a th's data-sort value to a comparable value on one row.
function makeSortable(table, stateKey, accessors, getRows, render) {
  $all("th[data-sort]", table).forEach(th => {
    th.innerHTML = th.textContent + ' <span class="sort-arrow">↕</span>';
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      const s = state.sort[stateKey];
      s.dir = s.key === key ? -s.dir : 1;
      s.key = key;
      $all("th[data-sort]", table).forEach(h => h.classList.remove("sorted"));
      th.classList.add("sorted");
      $(".sort-arrow", th).textContent = s.dir === 1 ? "↑" : "↓";
      render(sortRows(getRows(), accessors, s));
    });
  });
}

function sortRows(rows, accessors, sortState) {
  if (!sortState.key || !accessors[sortState.key]) return rows;
  const accessor = accessors[sortState.key];
  return [...rows].sort((a, b) => {
    let av = accessor(a), bv = accessor(b);
    if (typeof av === "string") { av = av.toLowerCase(); bv = (bv || "").toLowerCase(); }
    if (av < bv) return -sortState.dir;
    if (av > bv) return sortState.dir;
    return 0;
  });
}

// ---- Meta (poll interval choices, shared by the refresh picker and the Settings form) ----
async function loadMeta() {
  try {
    const meta = await api("/api/meta");
    state.pollIntervals = meta.poll_intervals_seconds || state.pollIntervals;
    if (meta.version) $("#about-version").textContent = `Version ${meta.version}`;
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

// ---- Data source lookups ("who/what is this IP" — each off by default, see Settings) ----
async function loadSourcesEnabled() {
  try {
    const data = await api("/api/settings/sources");
    state.sourcesEnabled = data.sources.some(s => s.enabled);
  } catch (e) { state.sourcesEnabled = false; }
}

function ipCell(ip, port) {
  const portSuffix = port ? ":" + port : "";
  if (!state.sourcesEnabled) return `${ip}${portSuffix}`;
  return `<button class="ip-link" data-ip="${ip}">${ip}${portSuffix}</button><span class="lookup-results" data-ip-result="${ip}"></span>`;
}

function wireIPLookupClicks(root) {
  $all(".ip-link", root).forEach(btn => {
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.ip;
      const targets = $all(`[data-ip-result="${ip}"]`, root);
      targets.forEach(t => t.innerHTML = `<span class="lookup-line">looking up…</span>`);
      try {
        const data = await api(`/api/lookup?ip=${encodeURIComponent(ip)}`);
        const html = (data.results || []).map(r =>
          `<span class="lookup-line"><strong>${r.name || r.source}:</strong> ${r.error || r.summary || "no data"}</span>`
        ).join("") || `<span class="lookup-line">${data.note || "no data"}</span>`;
        targets.forEach(t => t.innerHTML = html);
      } catch (err) {
        targets.forEach(t => t.innerHTML = `<span class="lookup-line">${err.message}</span>`);
      }
    });
  });
}

// ---- Settings: data sources table ----
function sourceStatusDot(s) {
  if (s.total_lookups === 0) return "off";
  if (s.last_ok) return "on";
  if (s.consecutive_failures >= 3) return "error";
  return "warn";
}

function sourceStatusText(s) {
  if (s.total_lookups === 0) return "not checked yet";
  if (s.last_ok) return "OK";
  return s.consecutive_failures >= 3 ? "failing" : "last check failed";
}

async function loadSources() {
  const data = await api("/api/settings/sources");
  state.sourcesEnabled = data.sources.some(s => s.enabled);
  const tbody = $("#sources-table tbody");
  tbody.innerHTML = data.sources.map(s => `
    <tr>
      <td><input type="checkbox" data-source-toggle="${s.key}" ${s.enabled ? "checked" : ""} ${data.writable ? "" : "disabled"}></td>
      <td>${s.name}</td>
      <td><span class="status-dot ${sourceStatusDot(s)}"></span>${sourceStatusText(s)}</td>
      <td>${s.total_lookups > 0 ? fmtTime(s.last_checked_at) : ""}</td>
      <td>${s.last_error ? s.last_error : ""}</td>
    </tr>
  `).join("");

  $all("input[data-source-toggle]", tbody).forEach(cb => {
    cb.addEventListener("change", async () => {
      const key = cb.dataset.sourceToggle;
      try {
        await api(`/api/settings/sources/${key}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: cb.checked }),
        });
        loadSources(); // recomputes state.sourcesEnabled from the server's response
      } catch (err) {
        cb.checked = !cb.checked;
        alert("Couldn't update source setting: " + err.message);
      }
    });
  });
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
const flowsTable = $("#flows-table");
const FLOW_ACCESSORS = {
  risk: f => f.RiskScore, protocol: f => f.Protocol, src: f => f.OriginSrc, dst: f => f.OriginDst,
  service: f => portService(f.DstPort), count: f => f._count || 1, direction: f => f.Direction || "",
  application: f => f.Application || "", state: f => f.TCPState || "", host: f => f.HostName || "",
  bytes: f => (f.TxBytes || 0) + (f.RxBytes || 0),
  first_seen: f => f.FirstSeen || "", last_seen: f => f.LastSeen || "", approved: f => f.Approved ? 1 : 0,
};
makeSortable(flowsTable, "flows", FLOW_ACCESSORS, () => state.rawFlows, renderFlows);

$("#flow-filters").addEventListener("submit", e => {
  e.preventDefault();
  loadFlows();
});
$("#group-by-dst").addEventListener("change", () => renderFlows(currentFlowRows()));

function currentFlowRows() {
  const rows = $("#group-by-dst").checked ? groupFlows(state.rawFlows) : state.rawFlows;
  return sortRows(rows, FLOW_ACCESSORS, state.sort.flows);
}

// groupFlows collapses rows that share protocol+src IP+dst IP+dst port —
// i.e. differ only by ephemeral src port — into one row per group, so a
// host making many short-lived connections to the same destination:port
// doesn't produce a wall of near-duplicate entries. The worst (highest)
// risk score in the group wins, since that's the one worth seeing.
function groupFlows(rows) {
  const groups = new Map();
  for (const f of rows) {
    const key = `${f.Protocol}|${f.OriginSrc}|${f.OriginDst}|${f.DstPort}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { ...f, _count: 1, SrcPort: null });
      continue;
    }
    g._count++;
    g.TxBytes = (g.TxBytes || 0) + (f.TxBytes || 0);
    g.RxBytes = (g.RxBytes || 0) + (f.RxBytes || 0);
    if (f.FirstSeen < g.FirstSeen) g.FirstSeen = f.FirstSeen;
    if (f.LastSeen > g.LastSeen) g.LastSeen = f.LastSeen;
    if (f.RiskScore > g.RiskScore) { g.RiskScore = f.RiskScore; g.RiskBucket = f.RiskBucket; g.RiskReasons = f.RiskReasons; }
    g.Approved = g.Approved || f.Approved;
  }
  return [...groups.values()];
}

async function loadFlows() {
  const form = $("#flow-filters");
  const params = new URLSearchParams();
  new FormData(form).forEach((v, k) => {
    if (k === "open_only") { if (v) params.set(k, "1"); return; }
    if (v) params.set(k, v);
  });
  const data = await api(`/api/firewalls/${state.firewallId}/flows?` + params.toString());
  state.rawFlows = data.flows;
  renderFlows(currentFlowRows());
  $("#flows-summary").textContent = `${data.flows.length} shown of ${data.total} matching`;
}

function renderFlows(rows) {
  const grouped = $("#group-by-dst").checked;
  const tbody = $("tbody", flowsTable);
  tbody.innerHTML = rows.map(f => `
    <tr class="${portCategoryClass(f.DstPort)}">
      <td>${riskBadgeButton(f.RiskBucket)}</td>
      <td>${f.Protocol}</td>
      <td>${ipCell(f.OriginSrc, grouped ? null : f.SrcPort)}</td>
      <td>${ipCell(f.OriginDst, f.DstPort)}</td>
      <td>${portService(f.DstPort)}</td>
      <td>${f._count > 1 ? "×" + f._count : ""}</td>
      <td>${f.Direction || ""}</td>
      <td>${f.Application || ""}</td>
      <td>${f.TCPState || ""}</td>
      <td>${f.HostName || ""}</td>
      <td>${fmtBytes((f.TxBytes || 0) + (f.RxBytes || 0))}</td>
      <td>${fmtTime(f.FirstSeen)}</td>
      <td>${fmtTime(f.LastSeen)}</td>
      <td>${approvedBadge(f.Approved)}</td>
      <td class="reasons-cell" title="${reasonsTitle(f.RiskReasons)}">${(f.RiskReasons || []).length ? "ⓘ" : ""}</td>
    </tr>
  `).join("");
  wireIPLookupClicks(tbody);
  $all(".risk-badge-btn", tbody).forEach((btn, i) => {
    btn.addEventListener("click", () => {
      const f = rows[i];
      openDetailModal(`${f.Protocol} ${f.OriginSrc} → ${f.OriginDst}${f.DstPort ? ":" + f.DstPort : ""}`, flowDetailHTML(f));
    });
  });
}

// ---- Ports & risk ----
const portsTable = $("#ports-table");
const PORT_ACCESSORS = {
  risk: u => u.RiskScore, protocol: u => u.Protocol, port: u => u.DstPort || 0, application: u => u.Application || "",
  samples: u => u.SampleCount, distinct_ips: u => u.DistinctDstIPs, bytes: u => u.TotalBytes,
  first_seen: u => u.FirstSeen || "", last_seen: u => u.LastSeen || "",
};
makeSortable(portsTable, "ports", PORT_ACCESSORS, () => state.portRows, renderPorts);

async function loadPorts() {
  state.portRows = await api(`/api/firewalls/${state.firewallId}/ports`);
  renderPorts(sortRows(state.portRows, PORT_ACCESSORS, state.sort.ports));
}

function renderPorts(rows) {
  const tbody = $("tbody", portsTable);
  tbody.innerHTML = rows.map(u => `
    <tr>
      <td>${riskBadgeButton(u.RiskBucket)}</td>
      <td>${u.Protocol}</td>
      <td>${u.DstPort || ""}</td>
      <td>${u.Application || ""}</td>
      <td>${u.SampleCount}</td>
      <td>${u.DistinctDstIPs}</td>
      <td>${fmtBytes(u.TotalBytes)}</td>
      <td>${fmtTime(u.FirstSeen)}</td>
      <td>${fmtTime(u.LastSeen)}</td>
      <td class="reasons-cell">${reasonsList(u.RiskReasons)}</td>
      <td>
        ${u.Approved
          ? `<button class="secondary" data-action="unapprove" data-protocol="${u.Protocol}" data-port="${u.DstPort}" data-app="${u.Application || ""}">Unapprove</button>`
          : `<button data-action="approve" data-protocol="${u.Protocol}" data-port="${u.DstPort}" data-app="${u.Application || ""}">Approve</button>`}
      </td>
    </tr>
  `).join("");

  $all(".risk-badge-btn", tbody).forEach((btn, i) => {
    btn.addEventListener("click", () => {
      const u = rows[i];
      openDetailModal(`${u.Protocol} port ${u.DstPort || "—"}${u.Application ? " (" + u.Application + ")" : ""}`, portDetailHTML(u));
      loadBucketConnections(u);
    });
  });

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
  loadSources();
  loadDatabaseInfo();

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

// ---- Settings: database size / clear ----
async function loadDatabaseInfo() {
  try {
    const data = await api("/api/settings/database");
    $("#database-size").textContent = `Current size: ${fmtBytes(data.size_bytes)} (${data.path})`;
  } catch (e) {
    $("#database-size").textContent = "";
  }
}

$("#database-clear").addEventListener("click", async () => {
  if (!confirm(
    "Clear the entire database? This permanently deletes all connection history, port stats, " +
    "approved ports, and cached lookups for every firewall. Your configured firewalls stay and " +
    "will start repopulating on their next poll. This cannot be undone."
  )) return;
  try {
    await api("/api/settings/database/clear", { method: "POST" });
    loadDatabaseInfo();
    loadFirewalls();
    refreshActiveTab();
  } catch (err) {
    alert("Couldn't clear the database: " + err.message);
  }
});

// ---- Boot ----
(async function init() {
  await loadMeta();
  await loadSourcesEnabled();
  await loadFirewalls();
  refreshActiveTab();
})();
