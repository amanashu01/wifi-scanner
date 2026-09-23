import pytest

from netguard import exposure, recon


@pytest.mark.parametrize("raw, expected", [
    ("https://example.com/path?q=1", "example.com"),
    ("HTTP://Sub.Example.COM:8443", "sub.example.com"),
    ("user@mail.example.org", "mail.example.org"),
    ("example.com.", "example.com"),
])
def test_clean_domain(raw, expected):
    assert recon.clean_domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "not a domain", "http://", "-bad.com", "a..b", "localhost"])
def test_clean_domain_rejects_junk(bad):
    with pytest.raises(ValueError):
        recon.clean_domain(bad)


def test_email_security_flags_missing_spf(monkeypatch):
    monkeypatch.setattr(recon, "_query", lambda *a, **k: [])
    monkeypatch.setattr(recon, "_HAVE_DNS", True)
    monkeypatch.setattr(recon, "_resolver", lambda: None)
    res = recon.email_security("example.com", txt_records=[])
    levels = {f["text"].split()[0]: f["level"] for f in res["findings"]}
    assert any(f["level"] == "bad" for f in res["findings"])   # no SPF/DMARC


def test_exposure_flags_cleartext_and_open_wifi():
    conns = [{"direction": "outgoing", "remote_port": 23, "remote_ip": "93.1.2.3",
              "remote_scope": "public", "process": "telnet", "local_port": 50000, "exposed": False},
             {"direction": "listening", "remote_port": 0, "remote_ip": "", "remote_scope": "any",
              "process": "python", "local_port": 80, "exposed": True}]
    r = exposure.audit(conns, [{"ssid": "cafe", "enc": "Open"}], connected_ssid="cafe")
    titles = " ".join(f["title"] for f in r["findings"])
    assert "Telnet" in titles and "HTTP" in titles and "insecure WiFi" in titles
    assert r["score"] < 60
    assert any(f["level"] == "bad" for f in r["findings"])


def test_exposure_clean_when_nothing_risky():
    r = exposure.audit([{"direction": "outgoing", "remote_port": 443, "remote_ip": "1.1.1.1",
                         "remote_scope": "public", "process": "curl", "local_port": 5000, "exposed": False}], [])
    assert r["score"] == 100
    assert any(f["level"] == "good" for f in r["findings"])
