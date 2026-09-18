# ============================================================
#  File: nullroute/core/http.py
#  HTTP client with retries, sane defaults, and per-request
#  metadata capture (status, size, content-type).
# ============================================================
from dataclasses import dataclass
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .errors import HttpError


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0 Safari/537.36 NULLROUTE/1.0"
)


@dataclass
class Response:
    url:           str
    status:        int
    content:       bytes
    headers:       dict
    content_type:  str = ""
    elapsed:       float = 0.0

    @property
    def text(self) -> str:
        enc = "utf-8"
        if "charset=" in self.content_type:
            enc = self.content_type.split("charset=")[-1].split(";")[0].strip()
        try:
            return self.content.decode(enc, errors="replace")
        except Exception:
            return self.content.decode("utf-8", errors="replace")

    @property
    def size(self) -> int:
        return len(self.content)


class HttpClient:
    def __init__(self, timeout: int = 20, user_agent: str = None,
                 verify: bool = False):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        retry = Retry(total=2, backoff_factor=0.4,
                      status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry,
                              pool_connections=32, pool_maxsize=32)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = verify

    def get(self, url: str, allow_redirects: bool = True) -> Optional[Response]:
        try:
            r = self.session.get(url, timeout=self.timeout,
                                 allow_redirects=allow_redirects)
            return Response(
                url=r.url,
                status=r.status_code,
                content=r.content,
                headers=dict(r.headers),
                content_type=r.headers.get("Content-Type", ""),
                elapsed=r.elapsed.total_seconds(),
            )
        except requests.RequestException as e:
            raise HttpError(f"{url}: {e}") from e
