# ============================================================
#  File: nullroute/analyzers/endpoints.py
#  Extract API endpoints, fetch/XHR calls, GraphQL ops.
# ============================================================
import re
from typing import List, Set
from urllib.parse import urljoin, urlsplit

from ..recon.js_fetcher import JsFile
from ..core.logger import Logger


# ---- direct URL matches ------------------------------------------------
_ABS_URL_RE  = re.compile(r"""https?://[^\s"'`<>\\]+""")
_QUOTED_PATH = re.compile(
    r"""["'`](/(?:api|v\d+|graphql|rest|internal|admin|_next|_nuxt|"""
    r"""wp-json|ajax|service|services)[A-Za-z0-9_\-/\.\?=&%]*)["'`]""",
    re.I)

# ---- fetch / XHR / axios -----------------------------------------------
_FETCH_RE = re.compile(
    r"""fetch\s*\(\s*["'`]([^"'`]+)["'`]""")
_AXIOS_RE = re.compile(
    r"""axios(?:\.\w+)?\s*\(\s*["'`]([^"'`]+)["'`]""")
_JQUERY_RE = re.compile(
    r"""\$\.(?:get|post|put|delete|ajax)\s*\(\s*["'`]([^"'`]+)["'`]""")
_XHR_RE = re.compile(
    r"""\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,"""
    r"""\s*["'`]([^"'`]+)["'`]""")

# ---- GraphQL -----------------------------------------------------------
_GQL_RE = re.compile(
    r"""(?:query|mutation|subscription)\s+(\w+)\s*(?:\(|{)""")


def _line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def analyze_endpoints(js_files: List[JsFile], logger: Logger,
                      base_url: str = "") -> List[dict]:
    findings: List[dict] = []
    seen: Set[str] = set()

    for js in js_files:
        if not js.content:
            continue
        c = js.content
        src = js.short_name

        # ---------- absolute URLs ----------
        for m in _ABS_URL_RE.finditer(c):
            url = m.group(0).rstrip(".,;)\"'`")
            # filter asset URLs and non-http
            if url.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg",
                             ".webp", ".css", ".woff", ".woff2",
                             ".ttf", ".eot", ".ico")):
                continue
            # only keep same-site URLs or api-like ones
            if base_url:
                base_host = urlsplit(base_url).netloc
                if url.startswith(("http://", "https://")) and \
                   urlsplit(url).netloc != base_host:
                    # keep but tag external
                    pass
            if url in seen:
                continue
            seen.add(url)
            findings.append({
                "kind": "Absolute URL",
                "severity": "INFO",
                "value": url,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- quoted path-style endpoints ----------
        for m in _QUOTED_PATH.finditer(c):
            path = m.group(1).rstrip(".,;")
            if path in seen:
                continue
            seen.add(path)
            findings.append({
                "kind": "API Path",
                "severity": "MEDIUM",
                "value": path,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- fetch() ----------
        for m in _FETCH_RE.finditer(c):
            url = m.group(1)
            if url in seen:
                continue
            seen.add(url)
            findings.append({
                "kind": "fetch() call",
                "severity": "MEDIUM",
                "value": url,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- axios ----------
        for m in _AXIOS_RE.finditer(c):
            url = m.group(1)
            if url in seen:
                continue
            seen.add(url)
            findings.append({
                "kind": "axios call",
                "severity": "MEDIUM",
                "value": url,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- jQuery ajax ----------
        for m in _JQUERY_RE.finditer(c):
            url = m.group(1)
            if url in seen:
                continue
            seen.add(url)
            findings.append({
                "kind": "jQuery ajax",
                "severity": "MEDIUM",
                "value": url,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- XHR ----------
        for m in _XHR_RE.finditer(c):
            method, url = m.group(1), m.group(2)
            key = f"{method} {url}"
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "kind": f"XHR {method}",
                "severity": "MEDIUM",
                "value": url,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

        # ---------- GraphQL ops ----------
        for m in _GQL_RE.finditer(c):
            op = m.group(1)
            key = f"gql:{op}"
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "kind": "GraphQL operation",
                "severity": "LOW",
                "value": op,
                "source": f"{src}:{_line_of(c, m.start())}",
            })

    # tag internal-ish endpoints as higher severity
    for f in findings:
        v = f["value"].lower()
        if any(t in v for t in ("/admin", "/internal", "/debug",
                                "/private", "/dev", "/staging",
                                "/api/internal", "/actuator")):
            f["severity"] = "HIGH"

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9),
                                 f["kind"], f["value"]))
    return findings
