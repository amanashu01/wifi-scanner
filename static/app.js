/* NetGuard dashboard - vanilla JS, no external libraries. */
"use strict";

const TOKEN = document.querySelector('meta[name="netguard-token"]').content;
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  tab: "overview",
  conns: [],
  dir: "all",
  history: [],          // [{t, rx, tx}] for the traffic chart
  firewall: null,
};
const HISTORY_POINTS = 60; // 60 samples * 2 s = 2 minutes

// ------------------------------------------------------------------ helpers
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtRate(bps) {
  return fmtBytes(bps) + "/s";
}
function fmtBytes(b) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b.toFixed(0) : b.toFixed(1)) + " " + u[i];
}
function endpoint(ip, port) {
  if (!ip && !port) return "";
  const host = ip.includes(":") ? "[" + ip + "]" : ip;
  return host + ":" + (port || "*");
}
async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", "X-NetGuard-Token": TOKEN, ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({ error: "Bad response from server" }));
  if (!res.ok || data.error) throw Object.assign(new Error(data.error || res.statusText), { data });
  return data;
}
let toastTimer;
function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 4000);
}

// --------------------------------------------------------------------- tabs
$$(".tab").forEach((b) => b.addEventListener("click", () => {
  state.tab = b.dataset.tab;
  $$(".tab").forEach((x) => x.classList.toggle("active", x === b));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + state.tab));
  if (state.tab === "traffic") drawChart();
  if (state.tab === "wifi" && !wifiLoaded) scanWifi();
}));

// -------------------------------------------------------------- connections
async function loadConnections() {
  try {
    const data = await api("/api/connections");
    state.conns = data.connections;
    renderSummary(data.summary);
    renderConnections();
    const note = $("#conn-note");
    note.textContent = data.note || "";
    note.classList.toggle("hidden", !data.note);
    $("#conn-meta").textContent = `${data.connections.length} sockets · source: ${data.source} · ` +
      `updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    $("#conn-body").innerHTML = `<tr><td colspan="7" class="empty">${esc(e.message)}</td></tr>`;
  }
}

function renderSummary(s) {
  $("#s-incoming").textContent = s.incoming;
  $("#s-outgoing").textContent = s.outgoing;
  $("#s-listening").textContent = s.listening;
  $("#s-exposed").textContent = s.exposed;
  $("#s-risky").textContent = s.risky;

  const list = (items, el, isIp) => {
    $(el).innerHTML = items.length ? items.map(([k, n]) =>
      `<li><span class="${isIp ? "mono" : ""}">${esc(k)}</span><span class="muted">${n}</span></li>`).join("")
      : '<li class="empty">Nothing yet</li>';
  };
  list(s.top_remotes, "#top-remotes", true);
  list(s.top_processes, "#top-procs", false);

  const exposed = state.conns.filter((c) => c.exposed);
  $("#exposed-list").innerHTML = exposed.length ? `<div class="table-wrap"><table>
    <thead><tr><th>Port</th><th>Proto</th><th>Bound to</th><th>Process</th><th></th></tr></thead><tbody>
    ${exposed.map((c) => `<tr>
      <td class="mono">${c.local_port}${riskTag(c)}</td><td>${c.proto}</td>
      <td class="mono">${esc(c.local_ip)}</td><td>${esc(c.process)} <span class="muted">${c.pid || ""}</span></td>
      <td>${blockPortBtn(c)}</td></tr>`).join("")}</tbody></table></div>`
    : '<p class="empty">No services are listening on the network. 👍</p>';
}

function riskTag(c) {
  return c.risk ? `<span class="tag risk" title="${esc(c.risk)}">⚠ risky</span>` : "";
}
function blockPortBtn(c) {
  if (!c.local_port) return "";
  if (c.port_blocked) return '<span class="tag blocked">port blocked</span>';
  return `<button class="small-btn danger" data-block="port" data-target="${c.local_port}"
    data-note="${esc(c.process)} listening on ${c.local_port}">Block port</button>`;
}
function blockIpBtn(c) {
  if (!c.remote_ip || ["loopback", "any"].includes(c.remote_scope)) return "";
  if (c.ip_blocked) return '<span class="tag blocked">IP blocked</span>';
  return `<button class="small-btn danger" data-block="ip" data-target="${esc(c.remote_ip)}"
    data-note="${esc(c.process)} ${c.direction}">Block IP</button>`;
}

function renderConnections() {
  const q = $("#conn-search").value.trim().toLowerCase();
  const hideLoop = $("#hide-loop").checked;
  const rows = state.conns.filter((c) => {
    if (state.dir !== "all" && c.direction !== state.dir) return false;
    if (hideLoop && (c.remote_scope === "loopback" ||
        (c.direction === "listening" && c.local_scope === "loopback"))) return false;
    if (!q) return true;
    return [c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.process, c.status, c.pid]
      .some((v) => String(v ?? "").toLowerCase().includes(q));
  });
  const order = { incoming: 0, listening: 1, outgoing: 2 };
  rows.sort((a, b) => order[a.direction] - order[b.direction] || a.local_port - b.local_port);

  $("#conn-body").innerHTML = rows.length ? rows.map((c) => `<tr>
      <td><span class="dir ${c.direction}">${c.direction}</span></td>
      <td>${c.proto}</td>
      <td class="mono">${esc(endpoint(c.local_ip, c.local_port))}${c.direction !== "outgoing" ? riskTag(c) : ""}</td>
      <td class="mono">${esc(endpoint(c.remote_ip, c.remote_port))}${
        c.remote_scope === "public" ? '<span class="tag public">public</span>' : ""}${
        c.direction === "outgoing" ? riskTag(c) : ""}</td>
      <td class="muted">${esc(c.status)}</td>
      <td>${esc(c.process)} <span class="muted">${c.pid || ""}</span></td>
      <td>${c.direction === "listening" ? blockPortBtn(c) : blockIpBtn(c)}</td>
    </tr>`).join("")
    : '<tr><td colspan="7" class="empty">No matching connections.</td></tr>';
}

$$("#dir-filter button").forEach((b) => b.addEventListener("click", () => {
  state.dir = b.dataset.dir;
  $$("#dir-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderConnections();
}));
$("#conn-search").addEventListener("input", renderConnections);
$("#hide-loop").addEventListener("change", renderConnections);

// Any "Block …" button in a table (event delegation)
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-block]");
  if (!btn) return;
  const { block, target, note } = btn.dataset;
  const what = block === "ip" ? `IP ${target}` : `port ${target}`;
  if (!confirm(`Block inbound traffic for ${what}?`)) return;
  btn.disabled = true;
  try {
    const rule = await api("/api/firewall/rules", {
      method: "POST", body: JSON.stringify({ kind: block, target, direction: "in", note }),
    });
    toast(`${rule.status === "simulated" ? "Simulated" : "Blocked"}: ${what}`);
    await Promise.all([loadFirewall(), loadConnections()]);
  } catch (err) {
    toast(err.message, true);
    btn.disabled = false;
  }
});

// ------------------------------------------------------------------ traffic
async function loadTraffic() {
  try {
    const d = await api("/api/traffic");
    state.history.push({ t: d.ts, rx: d.rx_rate, tx: d.tx_rate });
    if (state.history.length > HISTORY_POINTS) state.history.shift();
    $("#s-rx").textContent = $("#t-rx").textContent = fmtRate(d.rx_rate);
    $("#s-tx").textContent = $("#t-tx").textContent = fmtRate(d.tx_rate);
    $("#iface-body").innerHTML = d.interfaces.map((i) => `<tr>
      <td class="mono">${esc(i.name)}</td>
      <td class="num">${fmtRate(i.rx_rate)}</td><td class="num">${fmtRate(i.tx_rate)}</td>
      <td class="num">${fmtBytes(i.bytes_recv)}</td><td class="num">${fmtBytes(i.bytes_sent)}</td>
      <td class="num">${i.errin + i.errout}</td><td class="num">${i.dropin + i.dropout}</td></tr>`).join("");
    if (state.tab === "traffic") drawChart();
  } catch (e) {
    $("#iface-body").innerHTML = `<tr><td colspan="7" class="empty">${esc(e.message)}</td></tr>`;
  }
}

function drawChart() {
  const cv = $("#chart");
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight || 220;
  if (!w) return;
  cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext("2d");
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);

  const css = getComputedStyle(document.documentElement);
  const color = (v) => css.getPropertyValue(v).trim();
  const pad = { l: 64, r: 8, t: 8, b: 18 };
  const pts = state.history;
  const max = Math.max(1024, ...pts.map((p) => Math.max(p.rx, p.tx))) * 1.15;

  // grid + y labels
  g.font = "11px ui-monospace, Menlo, monospace";
  g.fillStyle = color("--muted");
  g.strokeStyle = color("--border");
  g.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (h - pad.t - pad.b) * (i / 4);
    g.beginPath(); g.moveTo(pad.l, y); g.lineTo(w - pad.r, y); g.stroke();
    g.fillText(fmtRate(max * (1 - i / 4)), 4, y + 4);
  }
  g.fillText("-2 min", pad.l, h - 4);
  g.fillText("now", w - pad.r - 22, h - 4);

  const x = (i) => pad.l + (w - pad.l - pad.r) * (i / (HISTORY_POINTS - 1));
  const y = (v) => pad.t + (h - pad.t - pad.b) * (1 - v / max);
  const offset = HISTORY_POINTS - pts.length;
  for (const [key, col] of [["rx", "--rx"], ["tx", "--tx"]]) {
    if (pts.length < 2) break;
    g.beginPath();
    pts.forEach((p, i) => (i ? g.lineTo : g.moveTo).call(g, x(i + offset), y(p[key])));
    g.strokeStyle = color(col);
    g.lineWidth = 2;
    g.stroke();
    g.lineTo(x(pts.length - 1 + offset), y(0));
    g.lineTo(x(offset), y(0));
    g.closePath();
    g.globalAlpha = 0.12; g.fillStyle = color(col); g.fill(); g.globalAlpha = 1;
  }
}
window.addEventListener("resize", () => state.tab === "traffic" && drawChart());

// ----------------------------------------------------------------- firewall
async function loadFirewall() {
  try {
    const fw = await api("/api/firewall");
    state.firewall = fw;
    const pill = $("#mode");
    pill.textContent = fw.mode === "live" ? "LIVE firewall" : fw.mode === "simulation" ? "Simulation mode" : "Firewall unsupported";
    pill.className = "pill " + fw.mode;

    const banner = $("#fw-banner");
    if (fw.mode === "live") {
      banner.className = "note live";
      banner.innerHTML = `<b>Live mode</b> — rules are applied to <b>${esc(fw.backend)}</b> immediately. ` +
        `Remove them here or run <code>python app.py --flush</code> when you are done.`;
    } else if (fw.mode === "simulation") {
      banner.className = "note";
      banner.innerHTML = `<b>Simulation mode</b> — NetGuard is not running as root/Administrator, so rules are ` +
        `recorded and the exact <b>${esc(fw.backend)}</b> commands are shown, but nothing is changed. ` +
        `Restart with <code>sudo python app.py</code> (or an Administrator terminal on Windows) to enforce them.`;
    } else {
      banner.className = "note";
      banner.textContent = `No supported firewall on ${fw.platform}.`;
    }

    $("#remove-all").disabled = !fw.rules.length;
    $("#rules").innerHTML = fw.rules.length ? fw.rules.slice().reverse().map((r) => `
      <div class="rule">
        <div class="rule-top">
          <div><span class="rule-title mono">${r.kind === "ip" ? esc(r.target) : "port " + esc(r.target) + "/" + esc(r.protocol)}</span>
            <span class="muted"> · ${esc(r.direction === "both" ? "in + out" : r.direction + "bound")}</span>
            <span class="status ${esc(r.status)}">${esc(r.status)}</span></div>
          <button class="small-btn" data-unblock="${esc(r.id)}">Unblock</button>
        </div>
        ${r.note ? `<div class="muted small">${esc(r.note)}</div>` : ""}
        <div class="muted small">added ${new Date(r.created * 1000).toLocaleString()}</div>
        <details><summary>Firewall commands</summary><pre>${esc(r.commands.join("\n\n"))}</pre></details>
      </div>`).join("")
      : '<p class="empty">No rules yet. Block something from the Connections tab or the form above.</p>';
  } catch (e) {
    $("#rules").innerHTML = `<p class="empty">${esc(e.message)}</p>`;
  }
}

$("#f-kind").addEventListener("change", (e) => {
  const port = e.target.value === "port";
  $("#f-proto-wrap").classList.toggle("hidden", !port);
  $("#f-target").placeholder = port ? "3389" : "203.0.113.7 or 10.0.0.0/24";
});

$("#rule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.target).entries());
  const msg = $("#form-msg");
  try {
    const r = await api("/api/firewall/rules", { method: "POST", body: JSON.stringify(body) });
    msg.className = "small ok";
    msg.textContent = (r.status === "simulated" ? "Recorded (simulated): " : "Blocked: ") + r.target;
    e.target.reset();
    $("#f-proto-wrap").classList.add("hidden");
    loadFirewall();
  } catch (err) {
    msg.className = "small err";
    msg.textContent = err.message;
  }
});

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-unblock]");
  if (!btn) return;
  btn.disabled = true;
  try {
    const res = await api("/api/firewall/rules/" + encodeURIComponent(btn.dataset.unblock), { method: "DELETE" });
    toast(res.error ? "Removed, but: " + res.error : "Rule removed", !!res.error);
  } catch (err) {
    toast(err.message, true);
  }
  loadFirewall();
  loadConnections();
});

$("#remove-all").addEventListener("click", async () => {
  if (!confirm("Remove every NetGuard firewall rule?")) return;
  try {
    const res = await api("/api/firewall/rules", { method: "DELETE" });
    toast(`Removed ${res.removed} rule(s)`);
  } catch (err) {
    toast(err.message, true);
  }
  loadFirewall();
  loadConnections();
});

// --------------------------------------------------------------------- wifi
let wifiLoaded = false, wifiBusy = false;
async function scanWifi() {
  if (wifiBusy) return;
  wifiBusy = true;
  wifiLoaded = true;
  $("#rescan").disabled = true;
  $("#wifi-status").textContent = "Scanning…";
  try {
    const nets = await api("/api/wifi");
    $("#wifi-list").innerHTML = nets.length ? nets.map((n, i) => {
      const p = n.percent || 0;
      const lvl = p >= 66 ? "good" : p >= 33 ? "ok" : "bad";
      const name = n.hidden ? "&lt;hidden&gt;" : esc(n.ssid || "<unnamed>");
      return `<div class="wifi">
        <div class="row1"><span class="ssid ${n.hidden ? "hid" : ""}">${name}</span>
          <span class="badge ${esc(n.enc)}">${esc(n.enc)}</span></div>
        <div class="meter"><div class="${lvl}" data-w="${p}"></div></div>
        <div class="row2"><span><b>${p}%</b>${n.rssi != null ? " (" + n.rssi + " dBm)" : ""}</span>
          <span>Ch <b>${n.channel}</b></span><span class="mono">${esc(n.bssid)}</span></div></div>`;
    }).join("") : '<p class="empty">No networks found.</p>';
    // widths are set through the DOM because the CSP forbids inline style attributes
    $$("#wifi-list .meter div").forEach((d) => { d.style.width = d.dataset.w + "%"; });
    $("#wifi-status").textContent = `${nets.length} networks · updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    $("#wifi-list").innerHTML = `<p class="empty">${esc(e.message)}</p>`;
    $("#wifi-status").textContent = "Error";
  } finally {
    wifiBusy = false;
    $("#rescan").disabled = false;
  }
}
$("#rescan").addEventListener("click", scanWifi);

// -------------------------------------------------------------------- loops
loadFirewall();
loadConnections();
loadTraffic();
setInterval(loadTraffic, 2000);
setInterval(() => { if ($("#conn-auto").checked && !document.hidden) loadConnections(); }, 4000);
setInterval(() => { if (state.tab === "wifi" && !document.hidden) scanWifi(); }, 20000);
