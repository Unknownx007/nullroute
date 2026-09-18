# ============================================================
#  File: nullroute/report/findings.py
#  Merge analyzer outputs into a single ordered list.
# ============================================================
from typing import List

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def build_findings(*groups: List[dict]) -> List[dict]:
    """Merge multiple lists of findings, dedupe by (kind, value)."""
    seen = set()
    out = []
    for group in groups:
        for f in group or []:
            key = (f.get("kind"), f.get("value"))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9),
                            f.get("kind", ""),
                            f.get("value", "")))
    return out
