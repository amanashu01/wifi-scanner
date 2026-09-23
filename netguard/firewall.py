"""
Firewall manager
================
Blocks an IP address / network, or a port (i.e. the service listening on it),
using the firewall that ships with your operating system:

  Linux   : iptables / ip6tables  - each rule is tagged with a comment
                                    "netguard:<id>" so we only touch our own rules
  macOS   : pf (packet filter)    - rules live in the anchor "com.apple/netguard",
                                    which the default /etc/pf.conf already loads,
                                    so the system config is never edited
  Windows : netsh advfirewall     - each rule is named "NetGuard-<id>"

Changing the firewall needs root / Administrator. Without it the app runs in
SIMULATION mode: rules are recorded and the exact commands are shown, but
nothing is executed. That makes it safe to explore and learn from.

Security notes (read these if you are learning!)
  * Every value that reaches a command is validated first (ipaddress module,
    integer port range) and commands are run as argument lists - never through
    a shell - so input like "1.2.3.4; rm -rf /" cannot inject commands.
  * Loopback and "block everything" (/0) rules are refused so you cannot lock
    yourself out of this dashboard.
"""

import ipaddress
import json
import os
import platform
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

PF_ANCHOR = "com.apple/netguard"
DIRECTIONS = ("in", "out", "both")
PROTOCOLS = ("tcp", "udp", "both")


class RuleError(ValueError):
    """Raised for invalid user input."""


@dataclass
class Rule:
    kind: str                       # "ip" | "port"
    target: str                     # "203.0.113.7", "10.0.0.0/8" or "3389"
    direction: str = "in"           # in | out | both
    protocol: str = "both"          # tcp | udp | both (port rules only)
    note: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    created: float = field(default_factory=time.time)
    status: str = "pending"         # active | simulated | error
    error: str = ""
    commands: list = field(default_factory=list)

    def label(self):
        if self.kind == "ip":
            return f"{self.target} ({self.direction})"
        return f"port {self.target}/{self.protocol} ({self.direction})"


@dataclass
class Command:
    argv: list
    stdin: str = None
    optional: bool = False          # failure is not fatal (e.g. no ip6tables)

    def display(self):
        text = " ".join(_quote(a) for a in self.argv)
        if self.stdin is not None:
            text += "  <<EOF\n" + self.stdin.rstrip("\n") + "\nEOF"
        return text


def _quote(arg):
    return f'"{arg}"' if (" " in arg or not arg) else arg


# ----------------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------------
def make_rule(kind, target, direction="in", protocol="both", note="",
              protected_ports=()):
    kind = str(kind).strip().lower()
    target = str(target).strip()
    direction = str(direction or "in").strip().lower()
    protocol = str(protocol or "both").strip().lower()
    # Notes end up inside a pf comment line: collapse newlines / control
    # characters so a note can never smuggle in an extra firewall rule.
    note = " ".join("".join(ch if ch.isprintable() else " " for ch in str(note or "")).split())[:120]

    if direction not in DIRECTIONS:
        raise RuleError(f"direction must be one of {DIRECTIONS}")
    if protocol not in PROTOCOLS:
        raise RuleError(f"protocol must be one of {PROTOCOLS}")

    if kind == "ip":
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise RuleError(f"'{target}' is not a valid IP address or CIDR network")
        if net.prefixlen == 0:
            raise RuleError("Refusing to block the entire internet (/0)")
        if net.is_loopback or net.is_unspecified:
            raise RuleError("Refusing to block loopback / unspecified addresses - "
                            "that would cut off this dashboard")
        # single hosts are stored without the /32 or /128 suffix
        target = str(net.network_address) if net.num_addresses == 1 else str(net)
    elif kind == "port":
        if not target.isdigit() or not 1 <= int(target) <= 65535:
            raise RuleError("port must be a number between 1 and 65535")
        target = str(int(target))
        if int(target) in protected_ports:
            raise RuleError(f"Refusing to block port {target}: the dashboard is using it")
    else:
        raise RuleError("kind must be 'ip' or 'port'")

    return Rule(kind=kind, target=target, direction=direction,
                protocol=protocol, note=note)


def _dirs(rule):
    return ("in", "out") if rule.direction == "both" else (rule.direction,)


def _protos(rule):
    return ("tcp", "udp") if rule.protocol == "both" else (rule.protocol,)


def _is_v6(target):
    return ipaddress.ip_network(target, strict=False).version == 6


# ----------------------------------------------------------------------------
# Backends - each turns a Rule into the OS commands that add / remove it
# ----------------------------------------------------------------------------
class IptablesBackend:
    name = "iptables (Linux)"

    def _specs(self, rule):
        """Yield (binary, chain, match-args) for each kernel rule we need."""
        tag = ["-m", "comment", "--comment", f"netguard:{rule.id}"]
        for d in _dirs(rule):
            chain = "INPUT" if d == "in" else "OUTPUT"
            if rule.kind == "ip":
                binary = "ip6tables" if _is_v6(rule.target) else "iptables"
                flag = "-s" if d == "in" else "-d"
                yield binary, chain, [flag, rule.target] + tag
            else:
                flag = "--dport" if d == "in" else "--sport"
                for p in _protos(rule):
                    for binary in ("iptables", "ip6tables"):
                        yield binary, chain, ["-p", p, flag, rule.target] + tag

    def _commands(self, rule, action):
        # a port rule is mirrored into ip6tables when available (optional)
        return [Command([b, action, chain] + spec + ["-j", "DROP"],
                        optional=(rule.kind == "port" and b == "ip6tables"))
                for b, chain, spec in self._specs(rule)]

    def add(self, rule, all_rules):
        return self._commands(rule, "-I")

    def remove(self, rule, all_rules):
        return self._commands(rule, "-D")


class PfBackend:
    """macOS pf. The whole anchor is rewritten from the rule list each time."""
    name = "pf (macOS)"

    def render(self, rules):
        lines = ["# Managed by NetGuard - do not edit by hand"]
        for r in rules:
            lines.append(f"# {r.id} {r.label()} {r.note}".rstrip())
            for d in _dirs(r):
                if r.kind == "ip":
                    if d == "in":
                        lines.append(f"block drop in quick from {r.target} to any")
                    else:
                        lines.append(f"block drop out quick from any to {r.target}")
                else:
                    protos = "{ tcp udp }" if r.protocol == "both" else r.protocol
                    # inbound: traffic TO our port; outbound: traffic FROM it
                    where = f"to any port {r.target}" if d == "in" else \
                            f"from any port {r.target} to any"
                    src = "from any " if d == "in" else ""
                    lines.append(f"block drop {d} quick proto {protos} {src}{where}")
        return "\n".join(lines) + "\n"

    def _load(self, rules):
        return [Command(["pfctl", "-a", PF_ANCHOR, "-f", "-"], stdin=self.render(rules)),
                Command(["pfctl", "-E"])]   # enable pf (reference counted, harmless)

    def add(self, rule, all_rules):
        return self._load(all_rules)

    def remove(self, rule, all_rules):
        remaining = [r for r in all_rules if r.id != rule.id]
        if not remaining:
            return [Command(["pfctl", "-a", PF_ANCHOR, "-F", "rules"])]
        return self._load(remaining)


class NetshBackend:
    name = "Windows Defender Firewall (netsh)"

    def add(self, rule, all_rules):
        cmds = []
        base = ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name=NetGuard-{rule.id}", "action=block"]
        for d in _dirs(rule):
            if rule.kind == "ip":
                cmds.append(Command(base + [f"dir={d}", f"remoteip={rule.target}"]))
            else:
                for p in _protos(rule):
                    port = "localport" if d == "in" else "remoteport"
                    cmds.append(Command(base + [f"dir={d}", f"protocol={p.upper()}",
                                                f"{port}={rule.target}"]))
        return cmds

    def remove(self, rule, all_rules):
        return [Command(["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name=NetGuard-{rule.id}"])]


def detect_backend(system=None):
    system = system or platform.system()
    return {"Linux": IptablesBackend, "Darwin": PfBackend,
            "Windows": NetshBackend}.get(system, lambda: None)()


def is_privileged():
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# ----------------------------------------------------------------------------
# Manager - keeps the rule list on disk and runs the commands
# ----------------------------------------------------------------------------
class FirewallManager:
    def __init__(self, store_path, backend=None, privileged=None, protected_ports=()):
        self.store = Path(store_path)
        self.backend = backend if backend is not None else detect_backend()
        self.privileged = is_privileged() if privileged is None else privileged
        self.protected_ports = set(protected_ports)
        self.lock = threading.Lock()
        self.rules = self._load()

    @property
    def mode(self):
        if self.backend is None:
            return "unsupported"
        return "live" if self.privileged else "simulation"

    # -- persistence ---------------------------------------------------------
    def _load(self):
        try:
            data = json.loads(self.store.read_text())
            return [Rule(**r) for r in data.get("rules", [])]
        except (FileNotFoundError, json.JSONDecodeError, TypeError):
            return []

    def _save(self):
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store.with_suffix(".tmp")
        tmp.write_text(json.dumps({"rules": [asdict(r) for r in self.rules]}, indent=2))
        tmp.replace(self.store)

    # -- execution -----------------------------------------------------------
    def _run(self, commands):
        """Run commands for real (live mode). Returns an error string or ''."""
        for cmd in commands:
            try:
                res = subprocess.run(cmd.argv, input=cmd.stdin, capture_output=True,
                                     text=True, timeout=20)
            except FileNotFoundError:
                if cmd.optional:
                    continue
                return f"command not found: {cmd.argv[0]}"
            except subprocess.TimeoutExpired:
                return f"timed out: {cmd.argv[0]}"
            # `pfctl -E` prints its token on stderr and returns 0; only fail on rc
            if res.returncode != 0 and not cmd.optional:
                return (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
        return ""

    # -- public API ----------------------------------------------------------
    def status(self):
        return {
            "mode": self.mode,
            "backend": self.backend.name if self.backend else None,
            "privileged": self.privileged,
            "platform": platform.system(),
            "rules": [asdict(r) for r in self.rules],
        }

    def add(self, kind, target, direction="in", protocol="both", note=""):
        if self.backend is None:
            raise RuleError(f"No firewall backend for {platform.system()}")
        rule = make_rule(kind, target, direction, protocol, note, self.protected_ports)
        with self.lock:
            dup = next((r for r in self.rules if r.kind == rule.kind and
                        r.target == rule.target and r.direction == rule.direction and
                        r.protocol == rule.protocol), None)
            if dup:
                raise RuleError(f"Already blocked: {dup.label()}")

            commands = self.backend.add(rule, self.rules + [rule])
            rule.commands = [c.display() for c in commands]
            if self.privileged:
                rule.error = self._run(commands)
                rule.status = "error" if rule.error else "active"
            else:
                rule.status = "simulated"
            if rule.status != "error":
                self.rules.append(rule)
                self._save()
        return rule

    def remove(self, rule_id):
        with self.lock:
            rule = next((r for r in self.rules if r.id == rule_id), None)
            if rule is None:
                raise RuleError("No such rule")
            commands = self.backend.remove(rule, self.rules)
            error = ""
            if self.privileged and rule.status == "active":
                error = self._run(commands)
            self.rules.remove(rule)
            self._save()
        return {"removed": rule.id, "commands": [c.display() for c in commands],
                "error": error}

    def remove_all(self):
        results = [self.remove(r.id) for r in list(self.rules)]
        return {"removed": len(results), "errors": [r["error"] for r in results if r["error"]]}

    def reapply(self):
        """Re-install saved rules (firewall rules usually vanish on reboot)."""
        if not self.privileged or self.backend is None:
            return
        with self.lock:
            for rule in self.rules:
                # remove first so iptables/netsh don't get duplicate entries
                self._run(self.backend.remove(rule, self.rules))
            for rule in self.rules:
                rule.error = self._run(self.backend.add(rule, self.rules))
                rule.status = "error" if rule.error else "active"
            self._save()
