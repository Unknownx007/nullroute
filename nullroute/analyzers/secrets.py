# ============================================================
#  File: nullroute/analyzers/secrets.py
#  Scan JS for hardcoded secrets.
# ============================================================
from typing import List
from urllib.parse import urlsplit

from ..recon.js_fetcher import JsFile
from ..data.secrets_patterns import PATTERNS, IGNORE_VALUES
from ..core.logger import Logger


MAX_VALUE_LEN = 100


def _line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _clean(value: str) -> str:
    return value.strip().strip("'\"`").strip()


def analyze_secrets(js_files: List[JsFile], logger: Logger) -> List[dict]:
    findings: List[dict] = []
    seen = set()

    for js in js_files:
        if not js.content:
            continue
        src_name = js.short_name
        for entry in PATTERNS:
            rgx = entry["_compiled"]
            for m in rgx.finditer(js.content):
                value = _clean(m.group(1) if m.groups() else m.group(0))
                if not value or len(value) < 6:
                    continue
                if value.lower() in IGNORE_VALUES:
                    continue
                if value.lower().startswith(("xxxx", "yyyy", "your_")):
                    continue
                if len(value) > MAX_VALUE_LEN:
                    value = value[:MAX_VALUE_LEN] + "…"

                key = (entry["kind"], value)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "kind": entry["kind"],
                    "severity": entry["severity"],
                    "value": value,
                    "source": f"{src_name}:{_line_of(js.content, m.start())}",
                    "url": js.url,
                })

    # sort by severity
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9),
                                 f["kind"]))
    return findings
