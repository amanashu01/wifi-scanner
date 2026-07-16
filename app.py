"""
WiFi Scanner - Web Application
==============================
A small Flask web app that lists the WiFi networks your own computer can see
and shows them on an auto-refreshing dashboard in your browser.

HOW IT WORKS (end to end)
  Backend  (this file): a Flask server with two routes
     GET /        -> serves the dashboard page
     GET /scan    -> asks the operating system for the visible networks,
                     parses the output, and returns it as JSON
  Frontend (templates string below): JavaScript calls /scan every few seconds,
     parses the JSON, and redraws the network list with signal-strength bars.

WHAT IT DOES / DOESN'T DO
  It reads the same public list of nearby access points that your OS already
  shows in the taskbar/menu bar (via the built-in OS command). It is passive:
  it does not connect to, transmit to, capture traffic from, or interfere with
  any network. It's the web equivalent of clicking the WiFi icon.

REQUIREMENTS
  pip install flask
  Then: python app.py   ->   open http://127.0.0.1:5000

PLATFORM NOTES
  Windows : uses `netsh wlan show networks mode=bssid`
  Linux   : uses `nmcli` (NetworkManager). Install with your package manager.
  macOS   : uses the `airport` tool. Newer macOS versions restrict this and may
            require Location Services permission for the terminal; if it returns
            nothing, that's an OS permission limitation, not a code bug.
"""

import platform
import subprocess
import re
import json
from flask import Flask, jsonify, Response

app = Flask(__name__)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def normalize_enc(raw: str) -> str:
    """Map the OS-specific security string to Open / WEP / WPA / WPA2 / WPA3."""
    if not raw:
        return "Open"
    r = raw.upper()
    if "WPA3" in r:
        return "WPA3"
    if "WPA2" in r:
        return "WPA2"
    if "WPA" in r:
        return "WPA"
    if "WEP" in r:
        return "WEP"
    if "OPEN" in r or r in ("", "--", "NONE"):
        return "Open"
    return raw  # unknown - pass through


def percent_to_dbm(percent: int) -> int:
    """Rough inverse of the common RSSI->% mapping, for display only."""
    return int(percent / 2) - 100


# ----------------------------------------------------------------------------
# Per-platform scanners. Each returns a list of dicts:
#   { ssid, bssid, percent, rssi, channel, enc, hidden }
# ----------------------------------------------------------------------------
def scan_windows():
    out = subprocess.check_output(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        text=True, stderr=subprocess.STDOUT, timeout=20,
    )
    networks = []
    current_ssid = None
    current_auth = "Open"
    entry = None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            current_ssid = m.group(1).strip()
            current_auth = "Open"
            continue
        m = re.match(r"^Authentication\s*:\s*(.*)$", line)
        if m:
            current_auth = m.group(1).strip()
            continue
        m = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            entry = {
                "ssid": current_ssid or "",
                "bssid": m.group(1).lower(),
                "percent": 0, "rssi": None, "channel": 0,
                "enc": normalize_enc(current_auth),
                "hidden": (current_ssid == ""),
            }
            networks.append(entry)
            continue
        m = re.match(r"^Signal\s*:\s*(\d+)%", line)
        if m and entry:
            entry["percent"] = int(m.group(1))
            entry["rssi"] = percent_to_dbm(entry["percent"])
            continue
        m = re.match(r"^Channel\s*:\s*(\d+)", line)
        if m and entry:
            entry["channel"] = int(m.group(1))
    return networks


def scan_linux():
    # Terse, machine-readable output. BSSID colons are escaped as "\:".
    out = subprocess.check_output(
        ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY",
         "dev", "wifi", "list"],
        text=True, stderr=subprocess.STDOUT, timeout=20,
    )
    networks = []
    for line in out.splitlines():
        if not line.strip():
            continue
        # Split on ':' that is NOT escaped with a backslash, then unescape.
        fields = [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", line)]
        if len(fields) < 5:
            continue
        ssid, bssid, signal, chan, security = fields[0], fields[1], fields[2], fields[3], fields[4]
        try:
            percent = int(signal)
        except ValueError:
            percent = 0
        try:
            channel = int(chan)
        except ValueError:
            channel = 0
        networks.append({
            "ssid": ssid,
            "bssid": bssid.lower(),
            "percent": percent,
            "rssi": percent_to_dbm(percent),
            "channel": channel,
            "enc": normalize_enc(security),
            "hidden": (ssid == ""),
        })
    return networks


def scan_macos():
    # Apple removed the `airport` tool in macOS 14.4+, so we use the built-in
    # `system_profiler`, which reports nearby networks as structured JSON.
    # Note: this source does not expose each network's BSSID (MAC address),
    # so that field is reported as "n/a".
    out = subprocess.check_output(
        ["system_profiler", "SPAirPortDataType", "-json"],
        text=True, stderr=subprocess.STDOUT, timeout=30,
    )
    data = json.loads(out)
    networks = []

    def channel_of(s):
        m = re.match(r"\s*(\d+)", str(s or ""))
        return int(m.group(1)) if m else 0

    def rssi_of(s):
        m = re.search(r"(-?\d+)\s*dBm", str(s or ""))
        return int(m.group(1)) if m else None

    def enc_of(s):
        r = str(s or "").lower()
        if "wpa3" in r:
            return "WPA3"
        if "wpa2" in r:
            return "WPA2"
        if "wpa" in r:
            return "WPA"
        if "wep" in r:
            return "WEP"
        if "none" in r or "open" in r:
            return "Open"
        return "WPA2"   # secured but unrecognised label

    def percent_of(rssi):
        if rssi is None:
            return 0
        if rssi <= -100:
            return 0
        if rssi >= -50:
            return 100
        return 2 * (rssi + 100)

    def add_net(entry):
        ssid = entry.get("_name", "")
        rssi = rssi_of(entry.get("spairport_signal_noise"))
        networks.append({
            "ssid": ssid,
            "bssid": "n/a",   # not exposed by system_profiler
            "percent": percent_of(rssi),
            "rssi": rssi,
            "channel": channel_of(entry.get("spairport_network_channel")),
            "enc": enc_of(entry.get("spairport_security_mode")),
            "hidden": (ssid == ""),
        })

    for block in data.get("SPAirPortDataType", []):
        for iface in block.get("spairport_airport_interfaces", []):
            current = iface.get("spairport_current_network_information")
            if isinstance(current, dict) and current.get("_name"):
                add_net(current)
            others = iface.get("spairport_airport_other_local_wireless_networks") or []
            for net in others:
                add_net(net)
    return networks


def scan_networks():
    system = platform.system()
    if system == "Windows":
        return scan_windows()
    if system == "Linux":
        return scan_linux()
    if system == "Darwin":
        return scan_macos()
    raise RuntimeError(f"Unsupported platform: {system}")


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/scan")
def scan_route():
    try:
        nets = scan_networks()
        # strongest first
        nets.sort(key=lambda n: n["percent"], reverse=True)
        return jsonify(nets)
    except FileNotFoundError as e:
        return jsonify({"error": f"Scan command not found: {e}. "
                                 f"Check the PLATFORM NOTES in app.py."}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Scan command failed: {e.output}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------------------------------------------------------------------
# Frontend (served at /)
# ----------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Scanner</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
    background: #0d1117; color: #e6edf3; padding: 18px; max-width: 760px; margin: 0 auto; }
  header { display: flex; align-items: baseline; justify-content: space-between;
    flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }
  h1 { font-size: 1.3rem; font-weight: 650; letter-spacing: -0.01em; }
  h1 .dot { color: #3fb950; }
  .sub { color: #8b949e; font-size: 0.82rem; }
  .bar-controls { display: flex; align-items: center; gap: 12px; margin: 16px 0; flex-wrap: wrap; }
  button { background: #21262d; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 8px; padding: 8px 14px; font-size: 0.85rem; cursor: pointer; transition: background 0.15s; }
  button:hover { background: #30363d; }
  button:disabled { opacity: 0.5; cursor: default; }
  .meta { color: #8b949e; font-size: 0.8rem; }
  .card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; }
  .row1 { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 8px; }
  .ssid { font-weight: 600; font-size: 0.98rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ssid.hidden { color: #8b949e; font-style: italic; font-weight: 500; }
  .badge { font-size: 0.7rem; padding: 3px 8px; border-radius: 20px; font-weight: 600; white-space: nowrap; }
  .bar-wrap { background: #0d1117; border-radius: 6px; height: 9px; overflow: hidden; margin: 8px 0; }
  .bar { height: 100%; border-radius: 6px; transition: width 0.4s ease; }
  .row2 { display: flex; gap: 14px; flex-wrap: wrap; color: #8b949e; font-size: 0.78rem; }
  .row2 b { color: #c9d1d9; font-weight: 600; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .empty, .error { text-align: center; padding: 30px 0; }
  .empty { color: #8b949e; }
  .error { color: #f85149; }
</style>
</head>
<body>
  <header>
    <h1><span class="dot">&#9679;</span> WiFi Scanner</h1>
    <span class="sub">web app &middot; passive scan</span>
  </header>
  <div class="bar-controls">
    <button id="rescan" onclick="scan()">Rescan now</button>
    <label class="meta"><input type="checkbox" id="auto" checked> Auto-refresh</label>
    <span class="meta" id="status">Loading&hellip;</span>
  </div>
  <div id="list"></div>
<script>
  function pctFromRssi(rssi) {
    if (rssi == null) return 0;
    if (rssi <= -100) return 0;
    if (rssi >= -50)  return 100;
    return 2 * (rssi + 100);
  }
  function barColor(p) {
    if (p >= 66) return "#3fb950";
    if (p >= 33) return "#d29922";
    return "#f85149";
  }
  function secStyle(enc) {
    if (enc === "Open") return "background:#3d1416;color:#f85149";
    if (enc === "WEP")  return "background:#3a2a10;color:#e3902a";
    if (enc === "WPA")  return "background:#33300f;color:#d4c419";
    return "background:#10331c;color:#3fb950";
  }
  let busy = false;
  async function scan() {
    if (busy) return;
    busy = true;
    const btn = document.getElementById('rescan');
    btn.disabled = true;
    document.getElementById('status').textContent = 'Scanning\u2026';
    try {
      const res = await fetch('/scan');
      const data = await res.json();
      if (data.error) { showError(data.error); return; }
      render(data);
      const t = new Date().toLocaleTimeString();
      document.getElementById('status').textContent =
        data.length + ' networks \u00B7 updated ' + t;
    } catch (e) {
      document.getElementById('status').textContent = 'Request failed - retrying';
    } finally {
      busy = false;
      btn.disabled = false;
    }
  }
  function showError(msg) {
    document.getElementById('list').innerHTML =
      '<div class="error">' + escapeHtml(msg) + '</div>';
    document.getElementById('status').textContent = 'Error';
  }
  function render(nets) {
    const list = document.getElementById('list');
    if (!nets.length) { list.innerHTML = '<div class="empty">No networks found.</div>'; return; }
    list.innerHTML = nets.map(n => {
      const p = (n.percent != null && n.percent > 0) ? n.percent : pctFromRssi(n.rssi);
      const name = n.hidden ? '&lt;hidden&gt;' : escapeHtml(n.ssid || '<unnamed>');
      const nameCls = n.hidden ? 'ssid hidden' : 'ssid';
      const rssiTxt = (n.rssi != null) ? (' (' + n.rssi + ' dBm)') : '';
      return `
        <div class="card">
          <div class="row1">
            <span class="${nameCls}">${name}</span>
            <span class="badge" style="${secStyle(n.enc)}">${n.enc}</span>
          </div>
          <div class="bar-wrap">
            <div class="bar" style="width:${p}%;background:${barColor(p)}"></div>
          </div>
          <div class="row2">
            <span><b>${p}%</b>${rssiTxt}</span>
            <span>Ch <b>${n.channel}</b></span>
            <span class="mono">${n.bssid}</span>
          </div>
        </div>`;
    }).join('');
  }
  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : s;
    return d.innerHTML;
  }
  setInterval(() => { if (document.getElementById('auto').checked) scan(); }, 10000);
  scan();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)