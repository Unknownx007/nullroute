# ============================================================
#  File: nullroute/recon/source_maps.py
#  Detect + attempt to fetch .map files referenced from JS.
# ============================================================
import re
from typing import List, Optional
from urllib.parse import urljoin

from .js_fetcher import JsFile
from ..core.http import HttpClient
from ..core.logger import Logger


# sourceMappingURL=main.js.map
_SRC_MAP_RE = re.compile(
    r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""", re.I)
# also catches /*# sourceMappingURL=... */ block form
_SRC_MAP_BLOCK_RE = re.compile(
    r"""/\*[#@]\s*sourceMappingURL\s*=\s*(\S+?)\s*\*/""", re.I)


def find_source_maps(js_files: List[JsFile], http: HttpClient,
                     logger: Logger) -> List[dict]:
    """
    For each JS file, look for a sourceMappingURL comment.  If found,
    try to fetch the map and report whether it's available.
    """
    results: List[dict] = []
    seen_urls = set()

    for js in js_files:
        if not js.content:
            continue
        maps = _SRC_MAP_RE.findall(js.content) + \
               _SRC_MAP_BLOCK_RE.findall(js.content)
        for m in maps:
            if m.startswith("data:"):
                continue
            absu = urljoin(js.url, m)
            if absu in seen_urls:
                continue
            seen_urls.add(absu)

            reachable = False
            size = 0
            try:
                r = http.get(absu)
                reachable = 200 <= r.status < 300
                size = r.size
            except Exception:
                pass

            results.append({
                "kind": "Source Map",
                "severity": "MEDIUM" if reachable else "INFO",
                "value": absu,
                "source": f"{js.short_name}:{_line_of(js.content, m)}",
                "reachable": reachable,
                "size": size,
            })
            if reachable:
                logger.find(f"source map: {absu}  ({size} bytes)")
            else:
                logger.info(f"source map (unreachable): {absu}")

    return results


def _line_of(content: str, needle: str) -> int:
    for i, line in enumerate(content.splitlines(), 1):
        if needle in line:
            return i
    return 0
