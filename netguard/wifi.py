"""
WiFi scanner
============
Lists the WiFi networks your own computer can already see, using the
operating system's built-in tools. Completely passive: nothing is
transmitted, captured or connected to.

  Windows : netsh wlan show networks mode=bssid
  Linux   : nmcli (NetworkManager)
  macOS   : system_profiler SPAirPortDataType -json
"""

import platform
import subprocess
import re
import json


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
