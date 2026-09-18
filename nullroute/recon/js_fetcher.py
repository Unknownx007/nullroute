# ============================================================
#  File: nullroute/recon/js_fetcher.py
#  Downloads JS files, tracks metadata, exposes inline JS too.
# ============================================================
import hashlib
import os
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

from ..core.http import HttpClient, Response
from ..core.logger import Logger


@dataclass
class JsFile:
    url:     str
    content: str = ""
    size:    int = 0
    status:  int = 0
    inline:  bool = False
    source_of_page: str = ""     # the HTML URL that referenced this file
    local_path: Optional[str] = None

    @property
    def short_name(self) -> str:
        return os.path.basename(urlsplit(self.url).path) or "inline.js"

    @property
    def hash(self) -> str:
        return hashlib.sha1(self.url.encode()).hexdigest()[:8]


class JsFetcher:
    def __init__(self, http: HttpClient, logger: Logger,
                 out_dir: Optional[str] = None):
        self.http = http
        self.log = logger
        self.out_dir = out_dir
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

    def fetch_one(self, url: str, page_url: str = "") -> Optional[JsFile]:
        try:
            r: Response = self.http.get(url)
        except Exception as e:
            self.log.warn(f"fetch failed: {url} — {e}")
            return None

        if r.status >= 400:
            self.log.warn(f"HTTP {r.status}: {url}")
            return None

        js = JsFile(
            url=url,
            content=r.text,
            size=r.size,
            status=r.status,
            source_of_page=page_url,
        )
        if self.out_dir:
            fname = f"{js.hash}_{js.short_name}"
            path = os.path.join(self.out_dir, fname)
            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(js.content)
            js.local_path = path
        return js

    def add_inline(self, text: str, page_url: str) -> JsFile:
        return JsFile(
            url=f"{page_url}#inline",
            content=text,
            size=len(text.encode("utf-8", "ignore")),
            status=200,
            inline=True,
            source_of_page=page_url,
        )
