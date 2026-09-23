# NetGuard: Network Monitor & Firewall Dashboard

**See what traffic is coming into and going out of your computer, and block it, from a local web dashboard.**

NetGuard is a hands-on learning tool for **cyber-security students**. It shows the network activity on your own machine and lets you block IP addresses and services with your operating system's firewall. Every firewall command it runs is displayed, so you can see how the rules work underneath.

> Built by **Ashutosh Singh**. Runs 100% locally on Windows, macOS and Linux. No cloud, no telemetry, no packet capture.

---

## Features

| Tab | What you get |
|-----|--------------|
| **Overview** | Counts of incoming, outgoing and listening connections, live download/upload speed, the top remote hosts and most active processes, and a list of **exposed services** (ports reachable from your network). |
| **Connections** | Every TCP/UDP socket on the machine, labelled **incoming / outgoing / listening**, with the local and remote address, state and **owning process + PID**. Public IPs and **risky ports** (Telnet, SMB, RDP, 4444…) are tagged. One-click **Block IP** / **Block port** buttons. |
| **Traffic** | A live throughput chart for the last 2 minutes, plus per-interface rates, total bytes, errors and dropped packets. |
| **Firewall** | Block an **IP address**, a **CIDR network** (`10.0.0.0/24`) or a **port/service**, inbound, outbound or both, TCP/UDP. The exact `iptables` / `pfctl` / `netsh` commands are shown for every rule. Unblock one rule or all of them. |
| **WiFi** | Nearby WiFi networks with signal strength, channel and security (Open / WEP / WPA / WPA2 / WPA3). Open and WEP networks are highlighted. |

### Safe by design
- **Simulation mode** by default. If you don't run it as root or Administrator, rules are recorded and their commands are shown, but **nothing on your system changes**, so you can explore safely.
- **Lock-out protection.** It refuses to block loopback (`127.0.0.1`, `::1`), `0.0.0.0/0`, or the port the dashboard itself runs on.
- **Only touches its own rules.** Rules are tagged (`netguard:<id>` in iptables, the `com.apple/netguard` pf anchor, `NetGuard-<id>` in Windows Firewall). Your existing firewall configuration is never edited.
- **Hardened local web app.** It binds to `127.0.0.1` only. A per-session API token blocks CSRF, a Host-header check blocks DNS rebinding, and it sends a strict Content-Security-Policy. All input is validated, and commands run without a shell, so command injection isn't possible.

---

## Quick start

**Requirements:** Python 3.9+ and `pip`.

```bash
git clone https://github.com/amanashu01/wifi-scanner.git netguard
cd netguard
```

### macOS / Linux
```bash
./run.sh            # simulation mode: safe, shows commands only
sudo ./run.sh       # live mode: really applies firewall rules
```

### Windows (PowerShell or CMD)
```bat
run.bat             :: simulation mode
```
To use live mode, right-click **Command Prompt → Run as administrator**, then run `run.bat`.

Then open **http://127.0.0.1:5050** in your browser.

<details>
<summary>Manual setup (without the scripts)</summary>

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                      # or: sudo .venv/bin/python app.py
```
</details>

### Command-line options
```
python app.py [--port 5050] [--host 127.0.0.1] [--flush] [--debug]

  --port    port for the dashboard (default 5050; macOS AirPlay already uses 5000)
  --host    interface to bind. Keep 127.0.0.1 unless you are in an isolated lab
  --flush   remove every NetGuard firewall rule and exit
```

> **Finished experimenting?** Click **Firewall → Remove all**, or run `sudo python app.py --flush`.

---

## How it works

```
 Browser (static/app.js)                   Flask (app.py)                 Operating system
 ───────────────────────                   ──────────────                 ────────────────
 Overview / Connections  ── GET /api/connections ──► netguard/connections.py ─► psutil / lsof  (socket table)
 Traffic chart           ── GET /api/traffic     ──► netguard/traffic.py     ─► interface byte counters
 WiFi                    ── GET /api/wifi        ──► netguard/wifi.py        ─► netsh / nmcli / system_profiler
 Firewall                ── POST/DELETE /api/firewall/rules
                             (X-NetGuard-Token)  ──► netguard/firewall.py    ─► iptables / pfctl / netsh
```

### How is a connection classified?
The OS keeps a table of every open socket. NetGuard reads it (the same data `netstat -an` or `lsof -i` prints) and labels each one:

| Label | Rule | Example |
|-------|------|---------|
| **listening** | socket in `LISTEN` state (or a UDP socket with no peer) | a web server waiting on `:80` |
| **incoming** | established, and our local port is one we listen on, so *they* connected to *us* | someone SSH-ing into your `:22` |
| **outgoing** | any other established connection, so *we* connected to *them* | your browser talking to `142.250.x.x:443` |

A listening socket bound to `0.0.0.0` or `::` is **exposed**, meaning other machines on the network can reach it. One bound to `127.0.0.1` is only reachable from your own computer.

### How is bandwidth measured?
The kernel counts the bytes sent and received on every interface. NetGuard reads those counters every 2 seconds and divides the change by the elapsed time: `rate = Δbytes / Δt`. No packets are captured.

### What does a block rule look like?

| OS | Firewall | Blocking inbound traffic from `203.0.113.7` |
|----|----------|--------------------------------|
| Linux | iptables | `iptables -I INPUT -s 203.0.113.7 -m comment --comment netguard:ab12cd34 -j DROP` |
| macOS | pf | `block drop in quick from 203.0.113.7 to any` (loaded into anchor `com.apple/netguard`) |
| Windows | Defender Firewall | `netsh advfirewall firewall add rule name=NetGuard-ab12cd34 action=block dir=in remoteip=203.0.113.7` |

Blocking a **port** stops the service listening on it from being reached. For example, blocking port `3389` blocks inbound RDP.

---

## Try these exercises

1. **Spot your own server.** Run `python3 -m http.server 8000` in another terminal. It shows up as an **exposed** listening service. Open `http://<your-LAN-IP>:8000` from your phone and watch an **incoming** connection appear.
2. **Block it.** Click **Block port** next to `8000` (in live mode). Reload the page on your phone and it will time out. Unblock it, and it works again.
3. **Who is your browser talking to?** Filter Connections by your browser's name and count the **public** IPs. Run `whois <ip>` on a few of them.
4. **Audit exposed services.** Check the Overview for any listening port marked ⚠ risky. Do you know why each one is open?
5. **Read the rules.** Add a rule in simulation mode, open **Firewall commands**, and run the same command yourself to learn the syntax.
6. **Watch a download.** Start a large download and watch the Traffic chart and the per-interface counters.

More background is in [docs/LEARNING.md](docs/LEARNING.md).

---

## Platform notes

| | Connections | Firewall | WiFi |
|---|---|---|---|
| **Linux** | psutil (run with `sudo` to see other users' processes) | `iptables` / `ip6tables` | `nmcli` (NetworkManager) |
| **macOS** | psutil if root, otherwise `lsof` (your own processes only) | `pf` via anchor `com.apple/netguard` | `system_profiler` (BSSID not exposed by macOS) |
| **Windows** | psutil | `netsh advfirewall` | `netsh wlan` |

- **Linux with nftables only:** most distros ship `iptables-nft`, which works transparently. If `iptables` is missing, install the `iptables` package.
- **Rules after a reboot:** OS firewall rules are usually cleared on reboot. NetGuard saves your rules in `data/rules.json` and re-applies them the next time you start it in live mode.
- **macOS WiFi names:** recent macOS versions may hide SSIDs unless the terminal has Location Services permission.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "Showing only your own processes" | Run with `sudo` (macOS/Linux) or as Administrator (Windows). |
| Port 5050 already in use | `python app.py --port 8080` |
| Rule shows **error** / "command failed" | Check that you are root/Administrator and that `iptables` / `pfctl` / `netsh` exists. |
| Lost connectivity after an experiment | `sudo python app.py --flush`. On macOS you can also run `sudo pfctl -a com.apple/netguard -F rules`. |
| No WiFi networks | Make sure WiFi is on. On macOS, grant Location Services to your terminal. On Linux, install NetworkManager. |

## Project layout

```
app.py                    Flask app: routes, security guards, CLI
netguard/
  connections.py          socket table → incoming / outgoing / listening + risk hints
  traffic.py              per-interface byte counters → live rates
  firewall.py             rule validation + iptables / pf / netsh backends
  wifi.py                 nearby WiFi networks (per-OS parsers)
templates/index.html      dashboard markup
static/app.js, style.css  dashboard logic & styles (no external libraries)
tests/                    pytest suite
docs/LEARNING.md          background concepts for learners
run.sh / run.bat          one-command setup & launch
```

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

The tests cover input validation, the command generated for each firewall backend (including injection attempts), connection parsing and classification, and the API's security checks. None of them touch your real firewall.

## ⚠️ Legal & ethical use

NetGuard is for **learning and for defending machines you own or are authorized to administer**. It inspects only the computer it runs on and never captures other people's traffic. Changing firewall rules can cut off network access, so experiment on a personal machine or a VM, and keep `--flush` handy.

## License

[MIT](LICENSE) © 2026 Ashutosh Singh
