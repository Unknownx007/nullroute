# ============================================================
#  File: nullroute/report/export.py
#  JSON and Markdown reports.
# ============================================================
import json
from datetime import datetime


def export_json(report: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path


MD_TEMPLATE = """# NULLROUTE Report — {target}

**Generated:** {ts}
**Tool:** NULLROUTE v1.0.0 — DEDSEC

---

## Summary

| Metric | Value |
|---|---|
| JS files analyzed | {js_count} |
| Total JS size | {js_size} |
| Secrets found | {secrets_n} |
| Endpoints found | {endpoints_n} |
| Hosts found | {hosts_n} |
| Source maps found | {maps_n} |

---

## Secrets

{secrets_section}

---

## Endpoints

{endpoints_section}

---

## Hosts

{hosts_section}

---

## Source Maps

{maps_section}

---

*"We don't break the app. We read its diary."*
"""


def _rows(findings):
    if not findings:
        return "_none_"
    lines = ["| # | Severity | Kind | Value | Source |",
             "|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        val = str(f.get("value", "")).replace("|", "\\|")
        src = str(f.get("source", "")).replace("|", "\\|")
        lines.append(
            f"| {i} | {f.get('severity','INFO')} | {f.get('kind','?')} "
            f"| `{val}` | `{src}` |")
    return "\n".join(lines)


def export_markdown(report: dict, path: str) -> str:
    stats = report.get("stats", {})
    md = MD_TEMPLATE.format(
        target=report.get("target", ""),
        ts=datetime.now().isoformat(timespec="seconds"),
        js_count=stats.get("js_count", 0),
        js_size=f"{stats.get('js_bytes', 0)/1024:.1f} KB",
        secrets_n=stats.get("secrets", 0),
        endpoints_n=stats.get("endpoints", 0),
        hosts_n=stats.get("hosts", 0),
        maps_n=stats.get("maps", 0),
        secrets_section=_rows(report.get("secrets", [])),
        endpoints_section=_rows(report.get("endpoints", [])),
        hosts_section=_rows(report.get("hosts", [])),
        maps_section=_rows(report.get("source_maps", [])),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    return path
