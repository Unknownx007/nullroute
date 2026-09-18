# ============================================================
#  File: nullroute/banner.py
#  DEDSEC 2D ASCII logo + animated wordmark + live scanline.
# ============================================================
import random
import shutil
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

from . import theme as T


# ================================================================
#  Quotes
# ================================================================
QUOTES = [
    "The browser sees everything. So do we.",
    "Every <script> is a confession.",
    "JavaScript never forgets.",
    "The frontend is the confession. The backend is the truth.",
    "They forgot what they shipped to you.",
    "You cannot hide what you send to the browser.",
    "Minification is not obfuscation.",
    "The source map is the confession booth.",
    "Every API endpoint has a story. We read them all.",
    "Source maps are the blueprint. Read carefully.",
    "In the bundle, there are no secrets. Only lazy developers.",
    "We don't break the app. We read its diary.",
    "The network is loud. The JavaScript is louder.",
    "Every minified bundle is a love letter to someone reading the source.",
    "In a world of obfuscation, be the deobfuscator.",
]


def quote() -> str:
    return random.choice(QUOTES)


# ================================================================
#  2D logo — hexagon reticle
# ================================================================
LOGO_2D = r"""
   ╔═══════════════════╗
   ║  ┏━━━━━━━━━━━━━┓  ║
   ║  ┃  ╲       ╱  ┃  ║
   ║  ┃   ╲     ╱   ┃  ║
   ║  ┃    ╲ N ╱    ┃  ║
   ║  ┃     ╲ ╱     ┃  ║
   ║  ┃      V      ┃  ║
   ║  ┃    ●───●    ┃  ║
   ║  ┗━━━━━━━━━━━━━┛  ║
   ╚═══════════════════╝
     ▼   ▼   ▼   ▼   ▼
"""


# ================================================================
#  ANSI helpers — bypass rich so we can do \r cleanly
# ================================================================
_CYAN    = "\033[38;2;0;212;255m"      # #00d4ff
_CYAN_D  = "\033[38;2;10;90;112m"      # dim cyan
_RED     = "\033[38;2;255;0;60m"       # #ff003c
_WHITE   = "\033[97m"
_DIM     = "\033[2m"
_BOLD    = "\033[1m"
_RESET   = "\033[0m"

_SCRAMBLE_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/\\~`ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _center_line(text: str) -> str:
    """Pad a plain-text line to center it in the terminal."""
    w = _term_width()
    t = len(text)
    if t >= w:
        return text
    return " " * ((w - t) // 2) + text


# ================================================================
#  Animated wordmark — scramble then lock in
# ================================================================
def _scramble_word(text: str, duration_per_char: float = 0.05) -> None:
    """
    Print an animated scramble effect.  Locks in character by character.
    Uses raw stdout with \r so it works reliably in any terminal.
    """
    locked = [" "] * len(text)

    for i in range(len(text)):
        # scramble this position and all later ones, 3 frames
        for _ in range(3):
            frame = "".join(
                locked[j] if j < i else random.choice(_SCRAMBLE_CHARS)
                for j in range(len(text))
            )
            sys.stdout.write(
                f"\r{_center_line(_BOLD + _CYAN + frame + _RESET)}")
            sys.stdout.flush()
            time.sleep(duration_per_char / 3)
        locked[i] = text[i]
        sys.stdout.write(
            f"\r{_center_line(_BOLD + _CYAN + ''.join(locked) + _RESET)}")
        sys.stdout.flush()
        time.sleep(duration_per_char / 2)

    sys.stdout.write("\n\n")
    sys.stdout.flush()


# ================================================================
#  Live scanline animation over the 2D logo
# ================================================================
def _scanline_logo(logo_lines: list[str], sweeps: int = 3,
                   frame_delay: float = 0.05) -> None:
    """
    Print the 2D logo with a bright cyan scanline sweeping top→bottom,
    `sweeps` times.  Each frame is redrawn in-place using cursor-up.
    """
    n = len(logo_lines)
    total_frames = sweeps * (n + 2)

    def render(active_row: int) -> list[str]:
        out = []
        for i, line in enumerate(logo_lines):
            centered = _center_line(line)
            if i == active_row:
                out.append(f"{_BOLD}{_CYAN}{centered}{_RESET}")
            elif i == active_row - 1 or i == active_row + 1:
                # dim neighbors make the sweep feel like a wave
                out.append(f"{_CYAN_D}{centered}{_RESET}")
            else:
                out.append(f"{_CYAN}{centered}{_RESET}")
        return out

    # initial paint
    sys.stdout.write("\n")
    for line in render(-1):
        sys.stdout.write(line + "\n")
    sys.stdout.flush()

    for f in range(total_frames):
        active = f % (n + 2)
        # move cursor up `n` lines and redraw
        sys.stdout.write(f"\033[{n}A")
        for line in render(active):
            sys.stdout.write(line + "\n")
        sys.stdout.flush()
        time.sleep(frame_delay)

    # final paint without highlight
    sys.stdout.write(f"\033[{n}A")
    for line in logo_lines:
        sys.stdout.write(f"{_CYAN}{_center_line(line)}{_RESET}\n")
    sys.stdout.flush()


# ================================================================
#  Banner
# ================================================================
def print_banner(console: Console = None, version: str = "1.0.0",
                 animate: bool = True) -> None:
    """
    Print the full NULLROUTE banner:
      • animated scramble wordmark
      • 2D logo with live scanline sweep
      • tagline · credits · quote
    All centered to the terminal width.
    """
    console = console or Console()

    # ---- header strip ----
    w = _term_width()
    strip = "▓▒░ INITIALIZING NULLROUTE ░▒▓"
    sys.stdout.write("\n")
    sys.stdout.write(f"{_CYAN_D}{_center_line(strip)}{_RESET}\n")
    sys.stdout.flush()
    console.print()

    # ---- animated wordmark ----
    if animate:
        _scramble_word(" N U L L R O U T E ")
    else:
        console.print(
            f"[bold {T.HEX['cyan']}]        N U L L R O U T E[/]",
            justify="center")
        console.print()

    # ---- 2D logo with scanline ----
    logo_lines = LOGO_2D.strip("\n").splitlines()
    if animate:
        _scanline_logo(logo_lines, sweeps=2, frame_delay=0.04)
    else:
        for line in logo_lines:
            console.print(f"[{T.HEX['cyan']}]{line}[/]",
                          justify="center")

    console.print()

    # ---- wordmark (again, now static and centered) ----
    console.print(
        f"[bold {T.HEX['cyan']}]N U L L R O U T E[/]",
        justify="center")
    console.print(
        f"[{T.HEX['text']}]J S   R E C O N   ·   S E C R E T   E X T R A C T I O N[/]",
        justify="center")
    console.print()

    # ---- info bar ----
    info = Text()
    info.append("version ", style=T.HEX["text_dim"])
    info.append(f"v{version}", style=T.HEX["cyan"])
    info.append("   ·   ", style=T.HEX["text_mute"])
    info.append("built by ", style=T.HEX["text_dim"])
    info.append("DEDSEC", style=f"bold {T.HEX['red']}")
    info.append("   ·   ", style=T.HEX["text_mute"])
    info.append("ghost in the bundle", style=T.HEX["text_dim"])
    console.print(Align.center(info))

    console.print()
    console.print(Align.center(
        f"[italic {T.HEX['amber']}]\"{quote()}\"[/]"
    ))
    console.print()


# ================================================================
def print_compact(console: Console = None, version: str = "1.0.0") -> None:
    console = console or Console()
    console.print(
        f"[{T.HEX['cyan']} b]◈ NULLROUTE[/]  "
        f"[{T.HEX['text_dim']}]v{version} · DEDSEC[/]"
    )


# ================================================================
def print_disclaimer(console: Console = None) -> None:
    console = console or Console()

    body = Text.from_markup(
        f"[{T.HEX['text']}]NULLROUTE performs [b]passive reconnaissance[/b] "
        f"against web applications: it fetches the HTML and JavaScript "
        f"your browser is served, extracts API endpoints, hardcoded "
        f"secrets, internal hostnames, and analyses source maps.[/]\n\n"

        f"[{T.HEX['amber']}]Use ONLY on:[/]\n"
        f"  • web applications you own,\n"
        f"  • authorized bug bounty targets (in-scope domains),\n"
        f"  • engagements with [b]written authorization[/b].\n\n"

        f"[{T.HEX['red_dim']}]Reconnaissance against systems you do not own "
        f"or lack explicit authorization for may violate computer-misuse "
        f"statutes, terms of service, and bug bounty program rules.\n\n"
        f"You are solely responsible for your use of this tool.[/]"
    )

    panel = Panel(
        body,
        title=f"[bold {T.HEX['red']}]⚠  LEGAL NOTICE  ⚠[/]",
        border_style=T.HEX["red"],
        padding=(1, 2),
    )
    console.print()
    console.print(panel)
    console.print()
