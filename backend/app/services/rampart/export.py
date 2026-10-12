"""Exporting an environment report: JSON, CSV, Markdown.

Everything here is built from rows the caller already fetched through
``repository``, so the scoping happened before this module was reached. It
formats; it does not query.

Two escaping concerns, both inherited from ``services.export`` rather than
reimplemented: Markdown special characters, and the spreadsheet formula
prefixes. They matter more here than in the per-CVE export, because these
cells contain text the owner typed rather than text a source published.
"""
from __future__ import annotations

import csv
import io

from app.services.export import cell, md, to_json  # noqa: F401  (to_json is re-exported)
from app.services.rampart import matching

STATE_ORDER = [matching.AFFECTED, matching.POSSIBLY_AFFECTED, matching.NOT_AFFECTED]

#: NVD hands back the whole description as a "title" for CVEs that have no
#: curated short name, and a 150-character Markdown heading is unreadable.
TITLE_LIMIT = 90


def _title(value) -> str:
    text = (value or "").strip()
    return text if len(text) <= TITLE_LIMIT else text[:TITLE_LIMIT].rsplit(" ", 1)[0] + "…"


STATE_TITLES = {
    matching.AFFECTED: "Affected",
    matching.POSSIBLY_AFFECTED: "Possibly affected — check by hand",
    matching.NOT_AFFECTED: "Ruled out",
}


def build(env, assets, matches, vulns: dict) -> dict:
    """The report, as data. Every renderer below takes this shape."""
    by_asset = {a.id: a for a in assets}
    rows = []
    for m in matches:
        asset = by_asset.get(m.asset_id)
        vuln = vulns.get(m.cve_id)
        rows.append({
            "cve_id": m.cve_id,
            "state": m.state,
            "method": m.method,
            "confidence": m.confidence,
            "evidence": m.evidence,
            "exposure": m.exposure,
            "asset": asset.label if asset else None,
            "asset_software": f"{asset.vendor} {asset.product}".strip() if asset else None,
            "asset_version": asset.version if asset else None,
            "title": _title(getattr(vuln, "title", None)) or None,
            "severity": getattr(vuln, "severity", None),
            "cvss_score": getattr(vuln, "cvss_score", None),
            "relevance_score": getattr(vuln, "relevance_score", None),
            "in_kev": bool(getattr(vuln, "in_kev", False)),
        })
    rows.sort(key=lambda r: (STATE_ORDER.index(r["state"]) if r["state"] in STATE_ORDER else 9,
                             -(r["relevance_score"] or 0)))
    return {
        "environment": env.name,
        "generated_at": None,  # filled by the caller, which owns the clock
        "assets": [
            {"label": a.label, "category": a.category, "vendor": a.vendor, "product": a.product,
             "version": a.version, "catalogued": a.catalogued, "hardware_model": a.hardware_model}
            for a in assets
        ],
        "matches": rows,
    }


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["state", "cve_id", "title", "severity", "cvss", "relevance", "in_kev",
                "asset", "software", "version", "method", "confidence", "evidence"])
    for r in report["matches"]:
        w.writerow([cell(v) for v in [
            r["state"], r["cve_id"], r["title"], r["severity"], r["cvss_score"], r["relevance_score"],
            "yes" if r["in_kev"] else "no", r["asset"], r["asset_software"], r["asset_version"],
            r["method"], r["confidence"], r["evidence"],
        ]])
    return buf.getvalue()


def to_markdown(report: dict) -> str:
    out = [f"# {md(report['environment'])}", ""]
    if report.get("generated_at"):
        out += [f"Generated {md(report['generated_at'])}.", ""]

    out += ["## Inventory", ""]
    if report["assets"]:
        out += ["| Asset | Software | Version | Category | |",
                "| --- | --- | --- | --- | --- |"]
        for a in report["assets"]:
            out.append(
                f"| {md(a['label'])} | {md(a['vendor'])} {md(a['product'])} | "
                f"{md(a['version']) or '—'} | {md(a['category'])} | "
                f"{'' if a['catalogued'] else 'unmatched'} |"
            )
    else:
        out.append("_Nothing registered._")
    out.append("")

    for state in STATE_ORDER:
        rows = [r for r in report["matches"] if r["state"] == state]
        if not rows:
            continue
        out += [f"## {STATE_TITLES[state]} ({len(rows)})", ""]
        for r in rows:
            flags = " · ".join(filter(None, [
                "CISA KEV" if r["in_kev"] else None,
                f"CVSS {r['cvss_score']}" if r["cvss_score"] is not None else None,
                f"relevance {r['relevance_score']}" if r["relevance_score"] is not None else None,
            ]))
            out.append(f"### {md(r['cve_id'])}{' — ' + md(r['title']) if r['title'] else ''}")
            if flags:
                out.append(f"{md(flags)}")
            out.append(f"- Asset: {md(r['asset'])} ({md(r['asset_software'])} {md(r['asset_version']) or '—'})")
            # The sentence is the reason this row exists; an export that dropped
            # it would be a list of CVE numbers with no argument attached.
            out.append(f"- Why: {md(r['evidence'])}")
            out.append("")

    out += ["---", "",
            "_Exported from Asber. The inventory in this file describes a live environment; "
            "treat it as you would a network diagram._"]
    return "\n".join(out)
