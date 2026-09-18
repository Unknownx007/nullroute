# ============================================================
#  File: nullroute/analyzers/hosts.py
#  Find internal hostnames, private IPs, and infrastructure
#  endpoints leaked into JS.
# ============================================================
import ipaddress
import re
from typing import List, Set

from ..recon.js_fetcher import JsFile
from ..core.logger import Logger


# ---- hostnames ---------------------------------------------------------
_INTERNAL_TLD_RE = re.compile(
    r"""\b([a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:local|internal|intranet|"""
    r"""lan|corp|dev|test|staging|admin|cluster\.local))\b""", re.I)

_HOSTNAME_RE = re.compile(
    r"""\b([a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?"""
    r"""(?:\.[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?){2,})\b""", re.I)

# ---- IPs ---------------------------------------------------------------
_IP_RE = re.compile(
    r"""\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b""")

# ---- Cloud infra hostnames (from CDNs / services) ----------------------
_CLOUD_INFRA_RE = re.compile(
    r"""\b([a-z0-9\-]+\.(?:s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|"""
    r"""execute-api\.[a-z0-9\-]+\.amazonaws\.com|"""
    r"""elb\.amazonaws\.com|"""
    r"""cloudfront\.net|"""
    r"""azurewebsites\.net|"""
    r"""blob\.core\.windows\.net|"""
    r"""googleapis\.com|"""
    r"""appspot\.com|"""
    r"""firebaseapp\.com))\b""", re.I)


# ---- filter out noise --------------------------------------------------
_IGNORE_HOSTS = {
    "w3.org", "schema.org", "w3c.org", "creativecommons.org",
    "googleapis.com", "gstatic.com", "google.com",
    "example.com", "example.org", "example.net",
    "localhost", "127.0.0.1", "0.0.0.0",
    "jquery.com", "jquery.org", "jquerymobile.com",
    "fontawesome.com", "bootstrapcdn.com",
    "cloudflare.com", "cloudflareinsights.com",
    "twitter.com", "facebook.com", "instagram.com",
    "youtube.com", "youtu.be", "linkedin.com", "pinterest.com",
    "gmail.com", "outlook.com", "yahoo.com",
    "npmjs.org", "npmjs.com", "unpkg.com", "jsdelivr.net",
    "cdnjs.com",
}


def _line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _is_public_tld(host: str) -> bool:
    if host in _IGNORE_HOSTS:
        return True
    parts = host.lower().split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        # a rough list of the TLDs a normal site has
        if tld in {"com", "net", "org", "io", "co", "dev", "app",
                   "ai", "gov", "edu", "io", "me", "sh", "xyz",
                   "cloud", "tech", "info", "biz", "tv", "cc",
                   "pk", "uk", "de", "fr", "jp", "in", "au", "ca"}:
            return True
    return False


def analyze_hosts(js_files: List[JsFile], logger: Logger) -> List[dict]:
    findings: List[dict] = []
    seen: Set[str] = set()

    for js in js_files:
        if not js.content:
            continue
        c = js.content
        src = js.short_name

        # ---------- private IPs ----------
        for m in _IP_RE.finditer(c):
            ip = m.group(1)
            try:
                _ = ipaddress.ip_address(ip)
            except Exception:
                continue
            if not _is_private_ip(ip):
                continue
            if ip in seen:
                continue
            seen.add(ip)
            findings.append({
                "kind": "Private IP",
                "severity": "HIGH",
                "value": ip,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- internal TLDs ----------
        for m in _INTERNAL_TLD_RE.finditer(c):
            host = m.group(1).lower()
            if host in seen:
                continue
            seen.add(host)
            findings.append({
                "kind": "Internal Hostname",
                "severity": "HIGH",
                "value": host,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- cloud infra ----------
        for m in _CLOUD_INFRA_RE.finditer(c):
            host = m.group(1).lower()
            if host in seen:
                continue
            seen.add(host)
            findings.append({
                "kind": "Cloud Infrastructure",
                "severity": "MEDIUM",
                "value": host,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- generic hostnames ----------
        for m in _HOSTNAME_RE.finditer(c):
            host = m.group(1).lower()
            if host in seen:
                continue
            if _is_public_tld(host):
                continue
            # filter obvious junk
            if host.endswith((".js", ".css", ".png", ".jpg",
                              ".jpeg", ".gif", ".svg", ".html",
                              ".json", ".xml")):
                continue
            if len(host) > 80:
                continue
            seen.add(host)
            findings.append({
                "kind": "Hostname",
                "severity": "LOW",
                "value": host,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9),
                                 f["kind"], f["value"]))
    return findings
