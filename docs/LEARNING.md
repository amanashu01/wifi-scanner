# Learning notes

Background on the concepts NetGuard shows you. Read it alongside the dashboard.

## 1. Ports, sockets and connections

- An **IP address** identifies a machine. A **port** (1–65535) identifies a program on that machine.
- A **socket** is one endpoint of a conversation: `IP:port`. A TCP **connection** is a pair of sockets: `192.168.1.5:52344 → 142.250.1.1:443`.
- A server **listens** on a well-known port (443 for HTTPS, 22 for SSH). Clients connect *from* a random high "ephemeral" port.
- **TCP states** you will see in the Connections tab:

| State | Meaning |
|-------|---------|
| `LISTEN` | waiting for connections |
| `ESTABLISHED` | connection is open and data can flow |
| `SYN_SENT` | we asked to connect and are waiting for a reply (many of these can mean a scan or a firewall drop) |
| `TIME_WAIT` / `CLOSE_WAIT` | the connection is closing |

**Command-line equivalents:** `netstat -an`, `ss -tunap` (Linux), `lsof -nP -i` (macOS/Linux), `Get-NetTCPConnection` (Windows PowerShell).

## 2. Attack surface

Every **exposed** listening port is a door into your machine. Security teams reduce the attack surface by:

1. Turning off services that aren't needed.
2. Binding internal services to `127.0.0.1` instead of `0.0.0.0`.
3. Using a firewall to block what has to stay running but shouldn't be reachable.

### Why some ports are flagged as risky
| Port | Service | Why it matters |
|------|---------|----------------|
| 21 / 23 | FTP / Telnet | Credentials travel in clear text, so anyone on the path can read them. |
| 445 | SMB | EternalBlue → WannaCry and NotPetya (2017). |
| 3389 | RDP | Heavily brute-forced; BlueKeep (CVE-2019-0708). |
| 4444 | none (by convention) | Default Metasploit reverse-shell port. Seeing it can indicate a compromise. |
| 6379 / 27017 / 9200 | Redis / MongoDB / Elasticsearch | Often deployed with no authentication, which has caused mass data leaks. |
| 1900 / 11211 | SSDP / Memcached | Abused for reflection and amplification DDoS. |

A flag is a **prompt to investigate**, not proof of an attack.

## 3. Firewalls

A host firewall checks every packet against an ordered list of rules. The first rule that matches decides what happens.

- **DROP** silently discards the packet, so the sender waits and times out. NetGuard uses this.
- **REJECT** discards the packet and tells the sender (TCP RST / ICMP unreachable), so the sender fails fast.
- **Inbound** rules stop others from reaching you. **Outbound** rules stop your programs from reaching others, which is useful for containing malware or blocking telemetry.

### The three backends
- **iptables (Linux):** rules sit in chains (`INPUT`, `OUTPUT`, `FORWARD`). `-I` inserts at the top, `-D` deletes. List them with `sudo iptables -L -n -v --line-numbers`.
- **pf (macOS/BSD):** rules are read top to bottom, and the last match wins unless a rule says `quick`. Anchors are named sub-rulesets. See NetGuard's with `sudo pfctl -a com.apple/netguard -s rules`.
- **Windows Defender Firewall:** managed with `netsh advfirewall` or `New-NetFirewallRule`. See NetGuard's rules with `netsh advfirewall firewall show rule name=all | findstr NetGuard`.

### Blocking an IP vs blocking a port
- **Block an IP** when a specific host is scanning or attacking you. Attackers can switch IPs, though, so this is reactive.
- **Block a port** to close a service to everyone. This is proactive attack-surface reduction.

## 4. Reading traffic numbers

- A steady upload you can't explain is worth investigating. Match it to a process in the Connections tab.
- A rising **errors** or **drops** count on an interface points to a bad cable or WiFi, a driver problem, or a flood of traffic.
- `lo` / `lo0` is loopback traffic. It never leaves your machine, so NetGuard leaves it out of the totals.

## 5. WiFi security at a glance

| Security | Verdict |
|----------|---------|
| **Open** | No encryption. Everyone nearby can read the traffic. Use a VPN or avoid it. |
| **WEP** | Broken since 2001 and can be cracked in minutes. |
| **WPA (TKIP)** | Deprecated. |
| **WPA2 (AES)** | Fine with a strong passphrase. KRACK has been patched on updated devices. |
| **WPA3** | Current standard. SAE resists offline password guessing. |

## 6. How NetGuard protects itself (web security lessons)

A local admin panel is a tempting target. These are the defences in `app.py`:

1. **Bind to 127.0.0.1**, so other machines can't reach the panel at all.
2. **CSRF token.** A malicious website you visit could otherwise send `POST http://127.0.0.1:5050/api/firewall/rules`. The token is embedded in the page, and the browser's same-origin policy stops other sites from reading it.
3. **Host-header check.** Stops **DNS rebinding**, where `evil.com` is re-resolved to `127.0.0.1` so the browser treats it as same-origin.
4. **Input validation plus argument lists.** IPs are parsed with `ipaddress`, ports must be integers, and commands run as `["iptables", "-s", ip]`, never through a shell string. `1.2.3.4; rm -rf /` is rejected.
5. **Content-Security-Policy.** Only the app's own scripts can run, which limits the damage any XSS bug could do.

## Further reading
- `man iptables`, `man pf.conf`, `man pfctl`, `netsh advfirewall /?`
- OWASP: *Cross-Site Request Forgery*, *DNS Rebinding*
- NIST SP 800-41 Rev. 1: *Guidelines on Firewalls and Firewall Policy*
