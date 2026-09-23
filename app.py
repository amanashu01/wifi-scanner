"""
NetGuard - network monitor & firewall dashboard
===============================================
A local web dashboard for learning how network traffic and host firewalls work.

  Overview    : headline numbers - who is connected, what is exposed
  Connections : every socket on this machine, classified as incoming /
                outgoing / listening, with the owning process
  Traffic     : live upload / download rate per network interface
  Firewall    : block an IP address, a network or a port (service)
  WiFi        : nearby WiFi networks and their security

Run
  pip install -r requirements.txt
  python app.py                 # simulation mode (firewall commands are shown, not run)
  sudo python app.py            # live mode (macOS / Linux)
  -> open http://127.0.0.1:5050

API (all JSON)
  GET    /api/connections        GET  /api/traffic       GET /api/wifi
  GET    /api/firewall           POST /api/firewall/rules
  DELETE /api/firewall/rules/<id>                        DELETE /api/firewall/rules
"""

import argparse
import secrets
import subprocess
import sys
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from netguard import __version__
from netguard import connections, exposure, password, recon, traffic, wifi
from netguard.firewall import FirewallManager, RuleError

BASE_DIR = Path(__file__).resolve().parent
RULES_FILE = BASE_DIR / "data" / "rules.json"

app = Flask(__name__)

# A random token created at start-up and embedded in the page. Requests that
# change the firewall must send it back in a header. Another website open in
# your browser cannot read our page, so it cannot learn the token - this stops
# cross-site request forgery (CSRF) against the firewall API.
API_TOKEN = secrets.token_urlsafe(32)
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
firewall = None  # created in main() once the port is known


# ----------------------------------------------------------------------------
# Request guards
# ----------------------------------------------------------------------------
@app.before_request
def check_host():
    # Rejecting unknown Host headers defeats DNS-rebinding attacks, where a
    # malicious domain is re-pointed at 127.0.0.1 to reach local services.
    host = request.host.rsplit(":", 1)[0] if not request.host.endswith("]") else request.host
    if app.config.get("CHECK_HOST", True) and host not in ALLOWED_HOSTS:
        abort(403, "Unexpected Host header")


def require_token(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not secrets.compare_digest(request.headers.get("X-NetGuard-Token", ""), API_TOKEN):
            return jsonify({"error": "missing or invalid API token"}), 403
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
    return resp


# ----------------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", token=API_TOKEN, version=__version__)


# ----------------------------------------------------------------------------
# Monitoring API
# ----------------------------------------------------------------------------
@app.route("/api/connections")
def api_connections():
    try:
        conns, source, note = connections.list_connections()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    blocked_ips = {r.target for r in firewall.rules if r.kind == "ip"}
    blocked_ports = {r.target for r in firewall.rules if r.kind == "port"}
    for c in conns:
        c["ip_blocked"] = c["remote_ip"] in blocked_ips
        c["port_blocked"] = str(c["local_port"]) in blocked_ports
    return jsonify({"connections": conns, "summary": connections.summarize(conns),
                    "source": source, "note": note})


@app.route("/api/traffic")
def api_traffic():
    try:
        return jsonify(traffic.sample())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/wifi")
def api_wifi():
    try:
        nets = wifi.scan_networks()
        nets.sort(key=lambda n: n["percent"], reverse=True)
        return jsonify(nets)
    except FileNotFoundError as e:
        return jsonify({"error": f"Scan command not found: {e}"}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Scan command failed: {e.output}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------------------------------------------------------------------
# Security tools: recon, exposure audit, password lab
# ----------------------------------------------------------------------------
@app.route("/api/recon")
def api_recon():
    try:
        return jsonify(recon.recon(request.args.get("domain", "")))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exposure")
def api_exposure():
    try:
        conns, _, _ = connections.list_connections()
    except Exception:
        conns = []
    nets, ssid = [], None
    try:
        nets = wifi.scan_networks()
    except Exception:
        pass
    return jsonify(exposure.audit(conns, nets, ssid))


@app.route("/api/password/analyze", methods=["POST"])
@require_token
def api_password_analyze():
    body = request.get_json(silent=True) or {}
    return jsonify(password.analyze(body.get("password", ""), body.get("info") or {}))


@app.route("/api/password/generate", methods=["POST"])
@require_token
def api_password_generate():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(password.generate(
            mode=body.get("mode", "passphrase"),
            words=body.get("words", 5), length=body.get("length", 20),
            separator=body.get("separator", "-"),
            capitalize=bool(body.get("capitalize", True)),
            add_number=bool(body.get("add_number", True))))
    except (ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400


# ----------------------------------------------------------------------------
# Firewall API
# ----------------------------------------------------------------------------
@app.route("/api/firewall")
def api_firewall():
    return jsonify(firewall.status())


@app.route("/api/firewall/rules", methods=["POST"])
@require_token
def api_add_rule():
    body = request.get_json(silent=True) or {}
    try:
        rule = firewall.add(body.get("kind"), body.get("target", ""),
                            body.get("direction", "in"), body.get("protocol", "both"),
                            body.get("note", ""))
    except RuleError as e:
        return jsonify({"error": str(e)}), 400
    except OSError as e:
        return jsonify({"error": f"Could not save rules: {e}"}), 500
    if rule.status == "error":
        return jsonify({"error": f"Firewall command failed: {rule.error}",
                        "commands": rule.commands}), 500
    return jsonify(firewall.status()["rules"][-1]), 201


@app.route("/api/firewall/rules/<rule_id>", methods=["DELETE"])
@require_token
def api_remove_rule(rule_id):
    try:
        return jsonify(firewall.remove(rule_id))
    except RuleError as e:
        return jsonify({"error": str(e)}), 404
    except OSError as e:
        return jsonify({"error": f"Could not save rules: {e}"}), 500


@app.route("/api/firewall/rules", methods=["DELETE"])
@require_token
def api_remove_all():
    try:
        return jsonify(firewall.remove_all())
    except OSError as e:
        return jsonify({"error": f"Could not save rules: {e}"}), 500


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------
def create_firewall(port):
    return FirewallManager(RULES_FILE, protected_ports={port})


def main(argv=None):
    global firewall
    parser = argparse.ArgumentParser(description="NetGuard network monitor & firewall dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to bind (default 127.0.0.1 - keep it local!)")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--flush", action="store_true",
                        help="remove every NetGuard firewall rule and exit")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    firewall = create_firewall(args.port)

    if args.flush:
        result = firewall.remove_all()
        print(f"Removed {result['removed']} rule(s).")
        for err in result["errors"]:
            print("  error:", err)
        return 0

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to a non-local address exposes a firewall-control "
              "panel to your network. Only do this in a lab.", file=sys.stderr)
        app.config["CHECK_HOST"] = False

    firewall.reapply()
    print(f"NetGuard {__version__}  |  firewall: {firewall.backend.name if firewall.backend else 'n/a'}"
          f"  |  mode: {firewall.mode.upper()}")
    if firewall.mode == "simulation":
        print("  Not running as root/Administrator - firewall changes will be simulated.")
    print(f"  Open http://127.0.0.1:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
