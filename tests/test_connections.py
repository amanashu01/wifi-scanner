from netguard.connections import classify, ip_scope, parse_lsof, summarize

LSOF = """COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
python3    1001 ash    3u  IPv4 0x1111111111111111      0t0  TCP *:8080 (LISTEN)
python3    1001 ash    4u  IPv4 0x2222222222222222      0t0  TCP 192.168.1.5:8080->192.168.1.20:51000 (ESTABLISHED)
Google\\x20  2002 ash   20u  IPv4 0x3333333333333333      0t0  TCP 192.168.1.5:52344->142.250.1.1:443 (ESTABLISHED)
rapportd    333 ash    5u  IPv6 0x4444444444444444      0t0  UDP *:5353
cupsd       444 root   6u  IPv6 0x5555555555555555      0t0  TCP [::1]:631 (LISTEN)
"""


def test_parse_lsof():
    conns = parse_lsof(LSOF)
    assert len(conns) == 5
    assert conns[0] == {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 8080,
                        "remote_ip": "", "remote_port": 0, "status": "LISTEN",
                        "pid": 1001, "process": "python3"}
    assert conns[2]["process"] == "Google "
    assert conns[2]["remote_ip"] == "142.250.1.1" and conns[2]["remote_port"] == 443
    assert conns[3]["proto"] == "udp" and conns[3]["local_port"] == 5353
    assert conns[4]["local_ip"] == "::1"


def test_classify_directions():
    conns = classify(parse_lsof(LSOF))
    dirs = [c["direction"] for c in conns]
    assert dirs == ["listening", "incoming", "outgoing", "listening", "listening"]
    assert conns[0]["exposed"] is True        # bound to all interfaces
    assert conns[4]["exposed"] is False       # loopback only
    assert conns[2]["remote_scope"] == "public"
    assert conns[1]["remote_scope"] == "private"


def test_risky_port_flagged():
    conns = classify([{"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 3389,
                       "remote_ip": "", "remote_port": 0, "status": "LISTEN",
                       "pid": 1, "process": "x"}])
    assert "RDP" in conns[0]["risk"]


def test_ip_scope():
    assert ip_scope("127.0.0.1") == "loopback"
    assert ip_scope("10.1.2.3") == "private"
    assert ip_scope("8.8.8.8") == "public"
    assert ip_scope("fe80::1%en0") == "link-local"
    assert ip_scope("") == "any"


def test_summarize():
    s = summarize(classify(parse_lsof(LSOF)))
    assert (s["incoming"], s["outgoing"], s["listening"]) == (1, 1, 3)
    assert ("142.250.1.1", 1) in s["top_remotes"]
