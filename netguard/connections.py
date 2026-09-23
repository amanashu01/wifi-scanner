"""
Connection monitor
==================
Answers the question "who is talking to my computer, and who is my computer
talking to?" by reading the operating system's socket table - the same data
that `netstat`, `ss` or `lsof -i` print.

Every socket is classified as one of:

  listening : a local service waiting for connections (e.g. a web server on :80)
  incoming  : an established connection that a remote host opened to one of
              our listening ports
  outgoing  : an established connection that we opened to a remote host

Data sources
  1. psutil.net_connections()  - fast and cross-platform, but on macOS it needs
                                 root to see sockets of other users' processes.
  2. `lsof -nP -i` (fallback)   - works without root on macOS/Linux, shows the
                                 current user's processes.
"""

import ipaddress
import re
import socket
import subprocess
from collections import Counter

try:
    import psutil
except ImportError:  # the app still runs; the lsof fallback is used instead
    psutil = None


# Ports that are worth a second look when you see them exposed or in use.
# This is an educational hint list, not a verdict - plenty of legitimate
# software uses these ports.
RISKY_PORTS = {
    21: "FTP - sends credentials in clear text",
    23: "Telnet - unencrypted remote shell",
    25: "SMTP - open relays are abused for spam",
    69: "TFTP - no authentication",
    135: "MS RPC - frequent worm target",
    137: "NetBIOS name service - leaks host info",
    139: "NetBIOS session - legacy file sharing",
    445: "SMB - target of WannaCry / EternalBlue",
    512: "rexec - legacy unauthenticated remote exec",
    513: "rlogin - legacy unauthenticated login",
    514: "rsh / syslog - legacy remote shell",
    1433: "MS SQL Server - should not face the internet",
    1900: "SSDP / UPnP - used in reflection DDoS",
    2323: "Alt Telnet - IoT botnets (Mirai)",
    3306: "MySQL - should not face the internet",
    3389: "RDP - brute-force and BlueKeep target",
    4444: "Common Metasploit / reverse-shell port",
    5432: "PostgreSQL - should not face the internet",
    5900: "VNC - often weakly protected",
    6379: "Redis - no auth by default",
    6667: "IRC - classic botnet command channel",
    9200: "Elasticsearch - often exposed without auth",
    11211: "Memcached - used in amplification DDoS",
    27017: "MongoDB - often exposed without auth",
    31337: "'Elite' backdoor port (Back Orifice)",
}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def ip_scope(ip: str) -> str:
    """Return loopback / private / link-local / multicast / public / unknown."""
    if not ip or ip in ("*", "0.0.0.0", "::"):
        return "any"
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])  # strip IPv6 zone id
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    return "public"


def classify(conns):
    """Fill in `direction` and `risk` for each connection dict (in place).

    A connection is "incoming" when its local port is one we are listening on;
    otherwise an established connection is "outgoing".
    """
    listening = {(c["proto"], c["local_port"]) for c in conns if c["status"] == "LISTEN"}
    # UDP has no LISTEN state; a UDP socket with no remote end is "bound".
    listening |= {("udp", c["local_port"]) for c in conns
                  if c["proto"] == "udp" and not c["remote_ip"]}

    for c in conns:
        if c["status"] == "LISTEN" or (c["proto"] == "udp" and not c["remote_ip"]):
            c["direction"] = "listening"
        elif (c["proto"], c["local_port"]) in listening:
            c["direction"] = "incoming"
        else:
            c["direction"] = "outgoing"

        port = c["local_port"] if c["direction"] != "outgoing" else c["remote_port"]
        c["risk"] = RISKY_PORTS.get(port)
        c["remote_scope"] = ip_scope(c["remote_ip"])
        c["local_scope"] = ip_scope(c["local_ip"])
        # A listening socket bound to 0.0.0.0 / :: is reachable from the network,
        # one bound to 127.0.0.1 only from this machine.
        c["exposed"] = c["direction"] == "listening" and c["local_scope"] not in ("loopback",)
    return conns


# ----------------------------------------------------------------------------
# Source 1: psutil
# ----------------------------------------------------------------------------
def _psutil_connections():
    names = {}
    out = []
    for s in psutil.net_connections(kind="inet"):
        proto = "tcp" if s.type == socket.SOCK_STREAM else "udp"
        name = None
        if s.pid:
            if s.pid not in names:
                try:
                    names[s.pid] = psutil.Process(s.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    names[s.pid] = None
            name = names[s.pid]
        status = s.status if s.status and s.status != "NONE" else ""
        out.append({
            "proto": proto,
            "local_ip": s.laddr.ip if s.laddr else "",
            "local_port": s.laddr.port if s.laddr else 0,
            "remote_ip": s.raddr.ip if s.raddr else "",
            "remote_port": s.raddr.port if s.raddr else 0,
            "status": status,
            "pid": s.pid,
            "process": name or "?",
        })
    return out


# ----------------------------------------------------------------------------
# Source 2: lsof  (fallback, no root needed for your own processes)
# ----------------------------------------------------------------------------
_ENDPOINT = re.compile(r"^\[?(?P<ip>[^\]]*?)\]?:(?P<port>\d+|\*)$")


def _split_endpoint(text):
    """'192.168.1.5:443' -> ('192.168.1.5', 443); '[::1]:631' -> ('::1', 631)."""
    m = _ENDPOINT.match(text)
    if not m:
        return "", 0
    ip = m.group("ip")
    if ip == "*":
        ip = "0.0.0.0"
    port = 0 if m.group("port") == "*" else int(m.group("port"))
    return ip, port


def parse_lsof(output: str):
    """Parse `lsof -nP -i` output into connection dicts."""
    out = []
    for line in output.splitlines()[1:]:  # skip header
        cols = line.split()
        if len(cols) < 9:
            continue
        command, pid, node = cols[0], cols[1], cols[7]
        name = " ".join(cols[8:])
        status = ""
        m = re.search(r"\((\w+)\)$", name)
        if m:
            status = m.group(1)
            name = name[:m.start()].strip()
        if "->" in name:
            local, remote = name.split("->", 1)
        else:
            local, remote = name, ""
        lip, lport = _split_endpoint(local)
        rip, rport = _split_endpoint(remote) if remote else ("", 0)
        out.append({
            "proto": node.lower() if node.lower() in ("tcp", "udp") else "tcp",
            "local_ip": lip,
            "local_port": lport,
            "remote_ip": rip,
            "remote_port": rport,
            "status": status,
            "pid": int(pid) if pid.isdigit() else None,
            # lsof escapes spaces in command names as \x20
            "process": command.replace("\\x20", " "),
        })
    return out


def _lsof_connections():
    res = subprocess.run(["lsof", "-nP", "+c", "0", "-i"], capture_output=True, text=True, timeout=20)
    return parse_lsof(res.stdout)


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------
def list_connections():
    """Return (connections, source, note)."""
    note = None
    conns, source = None, None
    if psutil is not None:
        try:
            conns, source = _psutil_connections(), "psutil"
        except psutil.AccessDenied:
            note = ("Showing only your own processes. Run with sudo / as "
                    "Administrator to see every process's connections.")
    if conns is None:
        try:
            conns, source = _lsof_connections(), "lsof"
        except FileNotFoundError:
            raise RuntimeError("Neither psutil nor lsof is available. "
                               "Install psutil: pip install psutil")

    # De-duplicate (lsof lists one row per file descriptor).
    seen, unique = set(), []
    for c in conns:
        # skip unbound sockets (no local port, no peer) - they carry no traffic
        if not c["local_port"] and not c["remote_ip"]:
            continue
        key = (c["proto"], c["local_ip"], c["local_port"], c["remote_ip"],
               c["remote_port"], c["pid"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return classify(unique), source, note


def summarize(conns):
    """Headline numbers for the overview page."""
    by_dir = Counter(c["direction"] for c in conns)
    remotes = Counter(c["remote_ip"] for c in conns
                      if c["remote_ip"] and c["remote_scope"] not in ("loopback", "any"))
    procs = Counter(c["process"] for c in conns if c["direction"] != "listening")
    return {
        "total": len(conns),
        "listening": by_dir.get("listening", 0),
        "incoming": by_dir.get("incoming", 0),
        "outgoing": by_dir.get("outgoing", 0),
        "exposed": sum(1 for c in conns if c["exposed"]),
        "risky": sum(1 for c in conns if c["risk"]),
        "top_remotes": remotes.most_common(8),
        "top_processes": procs.most_common(8),
    }
