# ============================================================
#  File: nullroute/core/logger.py
#  Structured logger that also drives the rich live display.
# ============================================================
import time
from datetime import datetime
from typing import Callable, List, Dict

from rich.console import Console

from .. import theme as T


LEVEL_STYLE = {
    "INFO":  T.HEX["cyan"],
    "OK":    T.HEX["green"],
    "WARN":  T.HEX["amber"],
    "ERR":   T.HEX["red"],
    "STEP":  T.HEX["cyan"],
    "DATA":  T.HEX["text"],
    "FIND":  T.HEX["red"],
    "HIT":   T.HEX["magenta"],
}


class Logger:
    def __init__(self, verbose: bool = True, quiet: bool = False,
                 console: Console = None):
        self.verbose = verbose
        self.quiet = quiet
        self.console = console or Console()
        self.records: List[Dict] = []
        self._subs: List[Callable[[Dict], None]] = []
        self.started = time.time()

    # ---- subscription (for a future TUI live feed) ----
    def subscribe(self, cb: Callable[[Dict], None]) -> None:
        self._subs.append(cb)

    # ---- emission ----
    def _emit(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        rec = {"ts": ts, "level": level, "msg": msg,
               "elapsed": round(time.time() - self.started, 3)}
        self.records.append(rec)

        if self.verbose and not self.quiet:
            style = LEVEL_STYLE.get(level, T.HEX["text"])
            tag = f"[{style}][{level:^5}][/]"
            self.console.print(
                f"[{T.HEX['text_dim']}]{ts}[/] {tag} {msg}")

        for cb in self._subs:
            try:
                cb(rec)
            except Exception:
                pass

    def info(self, m):  self._emit("INFO", m)
    def ok(self, m):    self._emit("OK", m)
    def warn(self, m):  self._emit("WARN", m)
    def err(self, m):   self._emit("ERR", m)
    def step(self, m):  self._emit("STEP", m)
    def data(self, m):  self._emit("DATA", m)
    def find(self, m):  self._emit("FIND", m)
    def hit(self, m):   self._emit("HIT", m)

    def dump(self) -> List[Dict]:
        return list(self.records)
