# ============================================================
#  File: nullroute/__main__.py
# ============================================================
import argparse
import os
import sys
import time
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress

from . import __version__, banner, theme as T
from .core.logger import Logger
from .core.http import HttpClient
from .core.errors import NullrouteError
from .core import ui
from .recon import (
    extract_script_urls, extract_script_urls_regex,
    extract_inline_scripts, JsFetcher, find_source_maps,
)
from .analyzers import analyze_secrets, analyze_endpoints, analyze_hosts
from .report import build_findings, export_json, export_markdown


# ================================================================
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="nullroute",
        description="NULLROUTE — JavaScript recon & secret extraction // DEDSEC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  nullroute https://example.com
  nullroute https://app.example.com --output ./scan
  nullroute https://example.com --no-inline --no-maps --json out.json
  nullroute https://example.com --quiet
""",
    )
    p.add_argument("target", help="URL to analyze")
    p.add_argument("-o", "--output", default="./nullroute_output",
                   help="output directory (default: ./nullroute_output)")
    p.add_argument("--timeout", type=int, default=20,
                   help="HTTP timeout (default 20)")
    p.add_argument("--no-inline", action="store_true",
                   help="skip inline <script> blocks")
    p.add_argument("--no-maps", action="store_true",
                   help="skip source map detection")
    p.add_argument("--json", metavar="PATH",
                   help="write JSON report to PATH")
    p.add_argument("--md", metavar="PATH",
                   help="write Markdown report to PATH")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="minimal output")
    p.add_argument("--no-anim", action="store_true",
                   help="skip the animated wordmark")
    p.add_argument("--version", action="version",
                   version=f"NULLROUTE {__version__} (DEDSEC)")
    return p.parse_args(argv)


# ================================================================
def normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ================================================================
def run(args, console: Console) -> int:
    target = normalize(args.target)
    logger = Logger(verbose=not args.quiet, console=console)

    # ---- banner ----
    if not args.quiet:
        banner.print_banner(console, __version__, animate=not args.no_anim)
        banner.print_disclaimer(console)

        # confirm
        console.print(
            f"[{T.HEX['amber']}]Do you have authorization to test this target?[/] ",
            end="")
        try:
            ans = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return 1
        if ans not in ("y", "yes"):
            console.print(f"[{T.HEX['red']}]Aborted.[/]")
            return 1

    # ---- prepare ----
    out_dir = os.path.abspath(args.output)
    js_dir = os.path.join(out_dir, "js")
    os.makedirs(js_dir, exist_ok=True)

    http = HttpClient(timeout=args.timeout)
    fetcher = JsFetcher(http, logger, out_dir=js_dir)

    started = time.time()

    # ---- 1. Fetch root HTML ----
    ui.section(console, "Fetching root document")
    try:
        root = http.get(target)
    except Exception as e:
        logger.err(f"could not fetch root: {e}")
        return 2

    logger.ok(f"GET {root.url}  →  HTTP {root.status}  "
              f"({root.size/1024:.1f} KB)")

    # ---- 2. Extract script refs ----
    ui.section(console, "Discovering scripts")
    ext_urls = extract_script_urls(root.text, root.url)
    ext_urls += [u for u in extract_script_urls_regex(root.text, root.url)
                 if u not in ext_urls]
    inline_scripts = [] if args.no_inline else extract_inline_scripts(root.text)

    logger.ok(f"external <script src> : {len(ext_urls)}")
    if not args.no_inline:
        logger.ok(f"inline <script>       : {len(inline_scripts)}")

    # ---- 3. Download JS files ----
    js_files = []
    if ext_urls:
        ui.section(console, "Downloading JavaScript")
        with ui.download_progress(console) as progress:
            task = progress.add_task(
                "[cyan]fetching JS…", total=len(ext_urls))
            for u in ext_urls:
                js = fetcher.fetch_one(u, page_url=root.url)
                if js:
                    js_files.append(js)
                    logger.ok(f"+ {js.short_name}  ({js.size/1024:.1f} KB)")
                progress.advance(task)

    for i, text in enumerate(inline_scripts):
        js_files.append(fetcher.add_inline(text, root.url))
    if inline_scripts:
        logger.ok(f"inline scripts captured: {len(inline_scripts)}")

    # ---- 4. Analyses ----
    ui.section(console, "Analyzing JavaScript")

    with ui.spinner(console, "scanning for secrets …"):
        secrets = analyze_secrets(js_files, logger)
    with ui.spinner(console, "extracting endpoints …"):
        endpoints = analyze_endpoints(js_files, logger, base_url=root.url)
    with ui.spinner(console, "hunting internal hosts …"):
        hosts = analyze_hosts(js_files, logger)
    maps = []
    if not args.no_maps:
        with ui.spinner(console, "checking source maps …"):
            maps = find_source_maps(js_files, http, logger)

    # ---- 5. Findings ----
    all_findings = build_findings(secrets, endpoints, hosts, maps)

    # ---- 6. Display ----
    console.print()
    if secrets:
        ui.highlight(console,
                     f"⚠  {len(secrets)} SECRETS EXPOSED",
                     "\n".join(
                         f"  [{f['severity']}] {f['kind']}  —  {f['value'][:60]}"
                         for f in secrets[:8]) +
                     ("\n  … and more" if len(secrets) > 8 else ""),
                     style=T.HEX["red"])

    ui.findings_table(console, secrets, title="SECRETS")
    ui.findings_table(console, endpoints, title="ENDPOINTS")
    ui.findings_table(console, hosts, title="HOSTS")
    if maps:
        ui.findings_table(console, maps, title="SOURCE MAPS")

    # ---- 7. Stats + summary ----
    js_bytes = sum(j.size for j in js_files)
    stats = {
        "elapsed":   round(time.time() - started, 2),
        "js_count":  len(js_files),
        "js_bytes":  js_bytes,
        "secrets":   len(secrets),
        "endpoints": len(endpoints),
        "hosts":     len(hosts),
        "maps":      len(maps),
    }
    ui.summary(console, root.url, stats)

    # ---- 8. Save reports ----
    report = {
        "tool":         "NULLROUTE",
        "version":      __version__,
        "target":       root.url,
        "generated":    time.strftime("%Y-%m-%dT%H:%M:%S"),
        "stats":        stats,
        "secrets":      secrets,
        "endpoints":    endpoints,
        "hosts":        hosts,
        "source_maps":  maps,
        "findings":     all_findings,
        "log":          logger.dump(),
    }

    json_path = args.json or os.path.join(
        out_dir, f"report_{int(time.time())}.json")
    export_json(report, json_path)
    logger.ok(f"JSON report → {json_path}")

    md_path = args.md or os.path.join(out_dir, "report.md")
    export_markdown(report, md_path)
    logger.ok(f"Markdown report → {md_path}")

    console.print()
    return 0


# ================================================================
def main(argv=None):
    args = parse_args(argv)
    console = Console()
    try:
        return run(args, console)
    except KeyboardInterrupt:
        console.print(f"\n[{T.HEX['red']}]interrupted.[/]")
        return 130
    except NullrouteError as e:
        console.print(f"[{T.HEX['red']}]error:[/] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
