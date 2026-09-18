# ============================================================
#  File: nullroute/recon/html_parser.py
#  Extract <script src> refs and inline <script> blocks.
# ============================================================
import re
from urllib.parse import urljoin, urlsplit
from typing import List, Tuple

from bs4 import BeautifulSoup


def extract_script_urls(html: str, base_url: str) -> List[str]:
    """
    Return a de-duplicated list of absolute URLs referenced by
    <script src="..."> tags.  Preserves order.
    """
    soup = BeautifulSoup(html, "html.parser")
    seen = set()
    out = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        absu = urljoin(base_url, src)
        # skip data: and javascript: pseudo-urls
        if absu.startswith(("data:", "javascript:", "blob:")):
            continue
        if absu in seen:
            continue
        seen.add(absu)
        out.append(absu)
    return out


def extract_inline_scripts(html: str) -> List[str]:
    """Return the text of every inline <script>...</script> block."""
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue
        text = tag.string
        if text:
            out.append(text)
    return out


# ---- regex fallback (catches scripts BS4 misses) ------------------
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)


def extract_script_urls_regex(html: str, base_url: str) -> List[str]:
    out = []
    seen = set()
    for m in _SCRIPT_SRC_RE.finditer(html):
        absu = urljoin(base_url, m.group(1))
        if absu in seen or absu.startswith(("data:", "javascript:")):
            continue
        seen.add(absu)
        out.append(absu)
    return out
