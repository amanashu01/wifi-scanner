import pytest

from netguard.firewall import (FirewallManager, IptablesBackend, NetshBackend,
                               PfBackend, RuleError, make_rule)


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("target, expected", [
    ("203.0.113.7", "203.0.113.7"),
    ("203.0.113.7/32", "203.0.113.7"),
    ("10.0.0.5/24", "10.0.0.0/24"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_ip_rules_are_normalised(target, expected):
    assert make_rule("ip", target).target == expected


@pytest.mark.parametrize("target", [
    "not-an-ip", "1.2.3.4; rm -rf /", "127.0.0.1", "::1", "0.0.0.0/0", "0.0.0.0", "",
])
def test_bad_or_dangerous_ips_are_refused(target):
    with pytest.raises(RuleError):
        make_rule("ip", target)


@pytest.mark.parametrize("target", ["0", "65536", "-1", "22; ls", "abc", ""])
def test_bad_ports_are_refused(target):
    with pytest.raises(RuleError):
        make_rule("port", target)


def test_dashboard_port_is_protected():
    with pytest.raises(RuleError):
        make_rule("port", "5050", protected_ports={5050})


def test_note_cannot_inject_pf_rules():
    r = make_rule("ip", "203.0.113.7", note="hi\npass in quick all\r\x00")
    assert "\n" not in r.note and "\r" not in r.note
    rules = [l for l in PfBackend().render([r]).splitlines() if not l.startswith("#")]
    assert rules == ["block drop in quick from 203.0.113.7 to any"]


def test_bad_direction_and_protocol():
    with pytest.raises(RuleError):
        make_rule("ip", "8.8.8.8", direction="sideways")
    with pytest.raises(RuleError):
        make_rule("port", "80", protocol="icmp")


# ------------------------------------------------------------------ backends
def argvs(cmds):
    return [c.argv for c in cmds]


def test_iptables_ip_both_directions():
    r = make_rule("ip", "203.0.113.7", direction="both")
    cmds = argvs(IptablesBackend().add(r, [r]))
    assert ["iptables", "-I", "INPUT", "-s", "203.0.113.7"] == cmds[0][:5]
    assert ["iptables", "-I", "OUTPUT", "-d", "203.0.113.7"] == cmds[1][:5]
    assert all(c[-2:] == ["-j", "DROP"] and f"netguard:{r.id}" in c for c in cmds)


def test_iptables_remove_mirrors_add():
    r = make_rule("port", "3389", protocol="tcp")
    b = IptablesBackend()
    added, removed = argvs(b.add(r, [r])), argvs(b.remove(r, [r]))
    assert [a[:1] + a[2:] for a in added] == [d[:1] + d[2:] for d in removed]
    assert {a[1] for a in added} == {"-I"} and {d[1] for d in removed} == {"-D"}


def test_iptables_ipv6_uses_ip6tables():
    r = make_rule("ip", "2001:db8::1")
    assert argvs(IptablesBackend().add(r, [r]))[0][0] == "ip6tables"


def test_pf_render():
    ip = make_rule("ip", "198.51.100.9", direction="both")
    port = make_rule("port", "23", protocol="tcp")
    text = PfBackend().render([ip, port])
    assert "block drop in quick from 198.51.100.9 to any" in text
    assert "block drop out quick from any to 198.51.100.9" in text
    assert "block drop in quick proto tcp from any to any port 23" in text


def test_pf_remove_last_rule_flushes_anchor():
    r = make_rule("ip", "198.51.100.9")
    assert argvs(PfBackend().remove(r, [r])) == [["pfctl", "-a", "com.apple/netguard", "-F", "rules"]]


def test_netsh_port_rule():
    r = make_rule("port", "445", protocol="both")
    cmds = argvs(NetshBackend().add(r, [r]))
    assert len(cmds) == 2
    assert f"name=NetGuard-{r.id}" in cmds[0] and "localport=445" in cmds[0]
    assert argvs(NetshBackend().remove(r, [r]))[0][-1] == f"name=NetGuard-{r.id}"


# ------------------------------------------------------------------- manager
def test_manager_simulation_persists_and_removes(tmp_path):
    store = tmp_path / "rules.json"
    fw = FirewallManager(store, backend=PfBackend(), privileged=False)
    rule = fw.add("ip", "203.0.113.7")
    assert rule.status == "simulated" and rule.commands
    with pytest.raises(RuleError):
        fw.add("ip", "203.0.113.7")          # duplicate

    reloaded = FirewallManager(store, backend=PfBackend(), privileged=False)
    assert [r.target for r in reloaded.rules] == ["203.0.113.7"]

    reloaded.remove(rule.id)
    assert FirewallManager(store, backend=PfBackend(), privileged=False).rules == []


def test_manager_live_mode_runs_commands(tmp_path, monkeypatch):
    ran = []

    class Result:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr("subprocess.run", lambda argv, **kw: ran.append(argv) or Result())
    fw = FirewallManager(tmp_path / "r.json", backend=IptablesBackend(), privileged=True)
    rule = fw.add("ip", "203.0.113.7")
    assert rule.status == "active"
    assert ran[0][:4] == ["iptables", "-I", "INPUT", "-s"]
