import pytest

import app as netguard_app
from netguard.firewall import FirewallManager, PfBackend


@pytest.fixture
def client(tmp_path):
    netguard_app.firewall = FirewallManager(tmp_path / "rules.json", backend=PfBackend(),
                                            privileged=False, protected_ports={5050})
    netguard_app.app.config["TESTING"] = True
    return netguard_app.app.test_client()


HEADERS = {"X-NetGuard-Token": netguard_app.API_TOKEN}


def test_index_embeds_token(client):
    html = client.get("/").get_data(as_text=True)
    assert netguard_app.API_TOKEN in html


def test_foreign_host_header_rejected(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403


def test_write_requires_token(client):
    r = client.post("/api/firewall/rules", json={"kind": "ip", "target": "203.0.113.7"})
    assert r.status_code == 403


def test_add_and_remove_rule(client):
    r = client.post("/api/firewall/rules", headers=HEADERS,
                    json={"kind": "ip", "target": "203.0.113.7"})
    assert r.status_code == 201 and r.json["status"] == "simulated"
    assert len(client.get("/api/firewall").json["rules"]) == 1
    assert client.delete(f"/api/firewall/rules/{r.json['id']}", headers=HEADERS).status_code == 200
    assert client.get("/api/firewall").json["rules"] == []


def test_invalid_rule_is_400(client):
    r = client.post("/api/firewall/rules", headers=HEADERS,
                    json={"kind": "port", "target": "5050"})
    assert r.status_code == 400 and "dashboard" in r.json["error"]
