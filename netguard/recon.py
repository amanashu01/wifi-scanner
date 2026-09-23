"""
Domain recon (passive)
=====================
Given a domain (e.g. "example.com"), gather the information that is *already
public* about it and explain what it means for security:

  DNS records      A / AAAA / MX / NS / TXT / SOA / CAA
  Email security   whether SPF, DMARC and DKIM are configured (their absence
                   lets anyone spoof email from the domain)
  TLS certificate  issuer, validity dates, days remaining, and the names it
                   covers - read by making a normal HTTPS connection
  HTTP headers     which security headers (HSTS, CSP, etc.) the site sets

Everything here is passive reconnaissance: it reads public DNS and makes one
ordinary HTTPS request, exactly like a browser. It does not scan, probe or
attack. Use it on domains you own or are authorized to assess.
"""

import re
import socket
import ssl
from datetime import datetime, timezone

try:
    import certifi
    _CA_FILE = certifi.where()
except ImportError:
    _CA_FILE = None


def _tls_context():
    """A verifying TLS context that uses certifi's CA bundle when available.

    Python builds on macOS/Windows sometimes ship without a usable system CA
    store, which makes every certificate look invalid; certifi fixes that.
    """
    return ssl.create_default_context(cafile=_CA_FILE)

try:
    import dns.resolver
    _HAVE_DNS = True
except ImportError:
    _HAVE_DNS = False

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                       r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# Security headers we check for, with a one-line "why it matters".
SECURITY_HEADERS = {
    "strict-transport-security": "Forces HTTPS, preventing downgrade attacks (HSTS).",
    "content-security-policy": "Limits where scripts can load from, blunting XSS.",
    "x-frame-options": "Stops the site being framed for clickjacking.",
    "x-content-type-options": "Stops browsers guessing content types (MIME sniffing).",
    "referrer-policy": "Controls how much URL info leaks to other sites.",
    "permissions-policy": "Restricts access to camera, mic, geolocation, etc.",
}


def clean_domain(raw):
    """Accept a URL or bare host and return the validated hostname."""
    d = str(raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)      # strip scheme
    d = d.split("/")[0].split("?")[0]     # strip path / query
    d = d.split("@")[-1]                  # strip any userinfo
    d = d.split(":")[0]                   # strip port
    d = d.strip(".")
    if not DOMAIN_RE.match(d):
        raise ValueError(f"'{raw}' is not a valid domain name.")
    return d


# ----------------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------------
def _resolver():
    r = dns.resolver.Resolver()
    r.timeout = 4
    r.lifetime = 6
    return r


def _query(resolver, name, rtype):
    try:
        return [rr.to_text() for rr in resolver.resolve(name, rtype)]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def dns_records(domain):
    if not _HAVE_DNS:
        return {"error": "dnspython is not installed (pip install dnspython)."}
    r = _resolver()
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"):
        records[rtype] = _query(r, domain, rtype)
    return records


def email_security(domain, txt_records=None):
    """Report SPF / DMARC / DKIM status from the domain's TXT records.

    Missing SPF or DMARC means anyone can send email that looks like it came
    from this domain - the root cause of a lot of phishing.
    """
    if not _HAVE_DNS:
        return {"error": "dnspython is not installed."}
    r = _resolver()
    txt = txt_records if txt_records is not None else _query(r, domain, "TXT")
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    dmarc = next((t for t in _query(r, f"_dmarc.{domain}", "TXT")
                  if "v=dmarc1" in t.lower()), None)
    # DKIM lives at selector._domainkey; we probe a few very common selectors.
    dkim = []
    for sel in ("default", "google", "selector1", "selector2", "k1", "mail", "s1"):
        if _query(r, f"{sel}._domainkey.{domain}", "TXT"):
            dkim.append(sel)

    dmarc_policy = None
    if dmarc:
        m = re.search(r"\bp=(\w+)", dmarc)
        dmarc_policy = m.group(1) if m else "none"

    findings = []
    findings.append(("good", "SPF record present.") if spf else
                    ("bad", "No SPF record - others can spoof email from this domain."))
    if dmarc:
        if dmarc_policy in ("none", None):
            findings.append(("warn", "DMARC present but policy is 'none' (monitor only, "
                                     "spoofed mail is still delivered)."))
        else:
            findings.append(("good", f"DMARC enforced (p={dmarc_policy})."))
    else:
        findings.append(("bad", "No DMARC record - spoofed email is not rejected."))
    findings.append(("good", f"DKIM selector(s) found: {', '.join(dkim)}.") if dkim else
                    ("warn", "No DKIM found on common selectors (it may use a custom one)."))

    return {"spf": spf, "dmarc": dmarc, "dmarc_policy": dmarc_policy,
            "dkim_selectors": dkim, "findings": [{"level": l, "text": t} for l, t in findings]}


# ----------------------------------------------------------------------------
# TLS certificate
# ----------------------------------------------------------------------------
def _name_tuples(seq):
    out = {}
    for rdn in seq or ():
        for k, v in rdn:
            out[k] = v
    return out


def tls_certificate(domain, port=443):
    """Read the TLS certificate by making a normal HTTPS connection."""
    ctx = _tls_context()
    try:
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Certificate did not validate: {e.verify_message}",
                "valid": False}
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"error": f"Could not connect over HTTPS: {e}"}

    def parse(dtstr):
        return datetime.strptime(dtstr, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    not_after = parse(cert["notAfter"])
    not_before = parse(cert["notBefore"])
    days_left = (not_after - datetime.now(timezone.utc)).days
    subject = _name_tuples(cert.get("subject"))
    issuer = _name_tuples(cert.get("issuer"))
    sans = [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"]

    findings = []
    if days_left < 0:
        findings.append(("bad", f"Certificate EXPIRED {abs(days_left)} days ago."))
    elif days_left < 15:
        findings.append(("bad", f"Certificate expires in {days_left} days - renew now."))
    elif days_left < 30:
        findings.append(("warn", f"Certificate expires in {days_left} days."))
    else:
        findings.append(("good", f"Certificate valid for {days_left} more days."))
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(("bad", f"Negotiated {version}, which is deprecated and insecure."))
    else:
        findings.append(("good", f"Negotiated {version}."))

    return {
        "valid": True,
        "subject_cn": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "not_before": not_before.strftime("%Y-%m-%d"),
        "not_after": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "sans": sans[:50],
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "findings": [{"level": l, "text": t} for l, t in findings],
    }


# ----------------------------------------------------------------------------
# HTTP security headers
# ----------------------------------------------------------------------------
def http_headers(domain):
    """One HEAD/GET over HTTPS; report which security headers are set."""
    import http.client
    try:
        conn = http.client.HTTPSConnection(domain, 443, timeout=6,
                                           context=_tls_context())
        conn.request("GET", "/", headers={"User-Agent": "NetGuard-Recon/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
    except Exception as e:
        return {"error": f"Could not fetch headers: {e}"}

    present, missing = [], []
    for h, why in SECURITY_HEADERS.items():
        (present if h in headers else missing).append({"header": h, "why": why})
    server = headers.get("server")
    findings = []
    if server and re.search(r"\d", server):
        findings.append({"level": "warn",
                         "text": f"'Server: {server}' header leaks exact software version."})
    return {"status": status, "server": server, "powered_by": headers.get("x-powered-by"),
            "present": present, "missing": missing, "findings": findings}


# ----------------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------------
def recon(domain):
    domain = clean_domain(domain)
    records = dns_records(domain)
    txt = records.get("TXT") if isinstance(records, dict) else None
    result = {
        "domain": domain,
        "dns": records,
        "email": email_security(domain, txt),
        "tls": tls_certificate(domain),
        "http": http_headers(domain),
    }
    resolved = bool(records.get("A") or records.get("AAAA")) if isinstance(records, dict) else False
    result["resolved"] = resolved
    return result
