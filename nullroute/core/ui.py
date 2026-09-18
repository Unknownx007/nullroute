# ============================================================
#  File: nullroute/core/ui.py
#  Rich-based boxes, panels, tables, section headers,
#  progress bars, and live-spinner helpers.
# ============================================================
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn, DownloadColumn,
    TransferSpeedColumn,
)
from rich.live import Live
from rich.align import Align

from .. import theme as T


# ================================================================
#  Section header — cyan banner strip
# ================================================================
def section(console: Console, title: str) -> None:
    txt = Text()
    txt.append("  ▓▒░ ", style=T.HEX["cyan_dim"])
    txt.append(title.upper(), style=f"bold {T.HEX['cyan']}")
    txt.append("  " + "░▒▓" * 1, style=T.HEX["cyan_dim"])
    console.print()
    console.rule(txt, style=T.HEX["cyan_dim"], align="left")


def subline(console: Console, text: str, style: str = None) -> None:
    console.print(f"  [{style or T.HEX['text_dim']}]{text}[/]")


# ================================================================
#  Key/value table — no borders, aligned
# ================================================================
def kv_table(console: Console, rows: list[tuple[str, str]],
             key_color: str = None, val_color: str = None) -> None:
    key_color = key_color or T.HEX["text_dim"]
    val_color = val_color or T.HEX["text"]
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(justify="right", style=key_color)
    table.add_column(justify="left", style=val_color)
    for k, v in rows:
        table.add_row(k, str(v))
    console.print(table)


# ================================================================
#  Findings table — bordered with severity coloring
# ================================================================
SEVERITY_STYLE = {
    "HIGH":   f"bold {T.HEX['red']}",
    "MEDIUM": f"bold {T.HEX['amber']}",
    "LOW":    f"{T.HEX['cyan']}",
    "INFO":   f"{T.HEX['text_dim']}",
}


def findings_table(console: Console, findings: list[dict],
                   title: str = "FINDINGS") -> None:
    if not findings:
        console.print(
            f"  [{T.HEX['text_dim']}]no findings.[/]")
        return

    table = Table(
        title=f"[bold {T.HEX['cyan']}]{title}[/]",
        title_justify="left",
        border_style=T.HEX["line"],
        header_style=f"bold {T.HEX['cyan']}",
        padding=(0, 1),
        show_lines=False,
    )
    table.add_column("#", justify="right", width=4,
                     style=T.HEX["text_dim"])
    table.add_column("SEVERITY", width=9)
    table.add_column("KIND", width=22, style=T.HEX["text"])
    table.add_column("VALUE", overflow="fold")
    table.add_column("SOURCE", overflow="fold", style=T.HEX["text_dim"])

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        sev_style = SEVERITY_STYLE.get(sev, T.HEX["text"])
        val = f.get("value", "")
        if len(val) > 70:
            val = val[:67] + "…"
        table.add_row(
            str(i),
            f"[{sev_style}]{sev}[/]",
            f.get("kind", "?"),
            f"[{T.HEX['white']}]{val}[/]",
            f.get("source", ""),
        )
    console.print(table)


# ================================================================
#  Progress bar for downloads
# ================================================================
@contextmanager
def download_progress(console: Console):
    progress = Progress(
        SpinnerColumn(style=T.HEX["cyan"]),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(
            bar_width=None,
            complete_style=T.HEX["cyan"],
            finished_style=T.HEX["green"],
            pulse_style=T.HEX["cyan_dim"],
        ),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("·"),
        DownloadColumn(),
        TextColumn("·"),
        TransferSpeedColumn(),
        console=console,
    )
    progress.start()
    try:
        yield progress
    finally:
        progress.stop()


# ================================================================
#  Spinner for long ops
# ================================================================
@contextmanager
def spinner(console: Console, text: str):
    with console.status(
        f"[{T.HEX['cyan']}]{text}[/]",
        spinner="dots12",
        spinner_style=T.HEX["cyan"],
    ) as status:
        yield status


# ================================================================
#  Highlight box for a single important finding
# ================================================================
def highlight(console: Console, title: str, body: str,
              style: str = None) -> None:
    style = style or T.HEX["red"]
    panel = Panel(
        Text(body, style=T.HEX["text"]),
        title=f"[bold {style}]{title}[/]",
        border_style=style,
        padding=(1, 2),
    )
    console.print(panel)


# ================================================================
#  Final summary box
# ================================================================
def summary(console: Console, target: str, stats: dict) -> None:
    body = Text()
    body.append("TARGET   ", style=T.HEX["text_dim"])
    body.append(f"{target}\n", style=T.HEX["cyan"])
    body.append("ELAPSED  ", style=T.HEX["text_dim"])
    body.append(f"{stats.get('elapsed', 0):.1f}s\n", style=T.HEX["text"])
    body.append("\n")
    body.append("JS FILES  ", style=T.HEX["text_dim"])
    body.append(f"{stats.get('js_count', 0):>4}\n", style=T.HEX["text"])
    body.append("SECRETS   ", style=T.HEX["text_dim"])
    body.append(f"{stats.get('secrets', 0):>4}\n",
                style=f"bold {T.HEX['red']}" if stats.get("secrets") else T.HEX["text"])
    body.append("ENDPOINTS ", style=T.HEX["text_dim"])
    body.append(f"{stats.get('endpoints', 0):>4}\n", style=T.HEX["text"])
    body.append("HOSTS     ", style=T.HEX["text_dim"])
    body.append(f"{stats.get('hosts', 0):>4}\n", style=T.HEX["text"])
    body.append("MAPS      ", style=T.HEX["text_dim"])
    body.append(f"{stats.get('maps', 0):>4}", style=T.HEX["text"])

    panel = Panel(
        body,
        title=f"[bold {T.HEX['green']}]◈ MISSION COMPLETE[/]",
        border_style=T.HEX["green"],
        padding=(1, 3),
    )
    console.print()
    console.print(panel)
