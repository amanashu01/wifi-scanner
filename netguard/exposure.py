"""
Password-exposure audit
=======================
Answers the question "could my network activity be leaking my passwords?"

It does NOT read any password. It reasons about the *channels* your traffic
uses. Credentials are exposed when they travel over a protocol that has no
encryption (so anyone on the same network or path can read them), so this
module flags:

  * connections on cleartext protocol ports (HTTP 80, FTP 21, Telnet 23,
    IMAP 143, POP3 110, SMTP 25, LDAP 389, ...) going to a non-local host
  * services YOU are exposing on those cleartext ports
  * being connected to an Open (unencrypted) WiFi network, where everything
    not individually encrypted is visible to others nearby

Each finding comes with what to do about it. This is a teaching aid, not a
guarantee - HTTPS-inside-a-tunnel and other cases can't be seen from here.
"""

# Cleartext protocols that commonly carry credentials, and their safe cousin.
CLEARTEXT_PORTS = {
    21: ("FTP", "SFTP/FTPS", "File-transfer logins are sent in the clear."),
    23: ("Telnet", "SSH", "Everything typed, including the password, is readable."),
    25: ("SMTP", "SMTP over TLS (465/587)", "Mail login can be sent unencrypted."),
    80: ("HTTP", "HTTPS", "Any login form or cookie on this page is unencrypted."),
    110: ("POP3", "POP3S (995)", "Mailbox password is sent in the clear."),
    143: ("IMAP", "IMAPS (993)", "Mailbox password is sent in the clear."),
    389: ("LDAP", "LDAPS (636)", "Directory/bind credentials are unencrypted."),
    512: ("rexec", "SSH", "Legacy unauthenticated/cleartext remote execution."),
    513: ("rlogin", "SSH", "Legacy cleartext remote login."),
    514: ("rsh", "SSH", "Legacy cleartext remote shell."),
    1433: ("MS SQL", "encrypted connection", "DB login may be sent unencrypted."),
    3306: ("MySQL", "TLS connection", "DB login may be sent unencrypted."),
    5432: ("PostgreSQL", "TLS connection", "DB login may be sent unencrypted."),
}


def audit(connections, wifi_networks=None, connected_ssid=None):
    """Return a list of exposure findings from live connection + WiFi data."""
    findings = []

    def add(level, title, detail, advice):
        findings.append({"level": level, "title": title, "detail": detail, "advice": advice})

    # --- cleartext connections -------------------------------------------
    for c in connections or []:
        remote_port = c.get("remote_port")
        local_port = c.get("local_port")
        scope = c.get("remote_scope")

        # a connection we opened to someone else's cleartext service
        if (c.get("direction") == "outgoing" and remote_port in CLEARTEXT_PORTS
                and scope not in ("loopback", "any")):
            proto, safe, why = CLEARTEXT_PORTS[remote_port]
            level = "bad" if scope == "public" else "warn"
            add(level, f"{proto} connection to {c.get('remote_ip')}:{remote_port}",
                f"{c.get('process')} is talking {proto} (unencrypted). {why}",
                f"Prefer {safe}. On untrusted networks assume this can be read.")

        # a cleartext service WE expose to the network
        if c.get("exposed") and local_port in CLEARTEXT_PORTS:
            proto, safe, why = CLEARTEXT_PORTS[local_port]
            add("bad", f"You are running {proto} on port {local_port}",
                f"{c.get('process')} is listening for {proto} on all interfaces. "
                f"Anyone who reaches it can capture credentials.",
                f"Switch the service to {safe}, or block port {local_port} in the "
                f"Firewall tab so it isn't reachable.")

    # --- open WiFi --------------------------------------------------------
    if connected_ssid:
        net = next((n for n in (wifi_networks or [])
                    if n.get("ssid") == connected_ssid), None)
        if net and net.get("enc") in ("Open", "WEP"):
            add("bad", f"Connected to an insecure WiFi network ({net['enc']})",
                f"'{connected_ssid}' uses {net['enc']} encryption. Others nearby can "
                f"read traffic that isn't individually encrypted.",
                "Use a VPN, or only visit HTTPS sites, and avoid logging in.")

    open_nearby = [n for n in (wifi_networks or []) if n.get("enc") == "Open"]
    if open_nearby and not connected_ssid:
        add("info", f"{len(open_nearby)} open WiFi network(s) nearby",
            "Open networks encrypt nothing. Joining one exposes cleartext traffic.",
            "Avoid entering passwords on open WiFi without a VPN.")

    # --- summary ----------------------------------------------------------
    score = 100 - sum({"bad": 25, "warn": 10, "info": 3}.get(f["level"], 0) for f in findings)
    score = max(0, score)
    if not findings:
        add("good", "No obvious cleartext credential exposure",
            "No connections on known unencrypted-login ports were seen, and you are "
            "not on an open WiFi network.",
            "Keep using HTTPS/SSH/TLS and re-check when your activity changes.")
    return {"score": score,
            "counts": {lvl: sum(1 for f in findings if f["level"] == lvl)
                       for lvl in ("bad", "warn", "info", "good")},
            "findings": findings}
