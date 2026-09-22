"""Per-threat export: JSON, CSV, Markdown."""
from __future__ import annotations

import csv
import io
import json
import re

# Escaping brackets is what neutralises [text](url) / ![img](url) injection;
# parentheses alone cannot form a link, so they stay readable in the output.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|])")


def md(text) -> str:
    """Escape external text for Markdown (prevents injected links/HTML in exported files)."""
    if text is None:
        return ""
    return _MD_SPECIAL.sub(r"\\\1", str(text)).replace("\n", " ")


def link(title, url) -> str:
    safe = str(url or "").replace(")", "%29").replace(" ", "%20")
    return f"[{md(title) or safe}]({safe})" if safe.startswith(("https://", "http://")) else md(title)


def to_json(detail: dict) -> str:
    return json.dumps(detail, indent=2, ensure_ascii=False)


FORMULA_PREFIXES = ("=", "+", "-", "@", chr(9), chr(13))


def _cell(value) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in FORMULA_PREFIXES else text


def to_csv(detail: dict) -> str:
    """Flat evidence list: one row per source / exploit / event."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["cve_id", "section", "title", "source", "tier", "date", "url"])
    cve = detail["cve_id"]
    ov = detail["overview"]
    rows = [[cve, "overview", ov.get("title"), "", "", ov.get("published"), ""]]
    for section in ("public_exploits", "pocs"):
        for e in detail[section]:
            rows.append([cve, section, e["title"], e["source"]["name"], e["tier"], e["published_at"], e["url"]])
    for ev in detail["timeline"]:
        rows.append([cve, f"timeline:{ev['kind']}", ev["title"], ev["source"], "", ev["date"], ev.get("url")])
    for s in detail["sources"]:
        rows.append([cve, f"source:{s['ref_type']}", s.get("title"), s["source"], s["tier"], s.get("published"),
                     s["url"]])
    for row in rows:
        w.writerow([_cell(c) for c in row])
    return buf.getvalue()


def to_markdown(d: dict) -> str:
    ov, kev, cvss = d["overview"], d.get("kev") or {}, d.get("cvss") or {}
    lines = [f"# {d['cve_id']}", ""]
    if ov.get("title"):
        lines += [f"**{md(ov['title'])}**", ""]
    lines += ["## Overview", "", md(ov.get("description") or "No description available."), "",
              f"- Vendor / product: {md(ov.get('vendor'))} / {md(ov.get('product'))}",
              f"- Published: {ov.get('published') or 'n/a'}",
              f"- CWE: {', '.join(ov.get('cwes') or []) or 'n/a'}", ""]

    lines += ["## Impact & Risk", "",
              f"- CVSS: {cvss.get('score') or 'n/a'} {cvss.get('severity') or ''} `{cvss.get('vector') or ''}`",
              f"- Threat Relevance Score: **{d['risk']['relevance_score']}** / 100 "
              f"(internal prioritisation, not CVSS)", ""]
    for r in d["risk"]["reasons"]:
        lines.append(f"  - +{r['points']} {md(r['factor'])} — {md(r['detail'])}")
    lines.append("")

    lines += ["## Affected Products", ""]
    lines += [f"- {md(p['vendor'])} {md(p['product'])} {md(p.get('versions') or '')}"
              for p in d["affected_products"][:50]] or ["- n/a"]
    lines.append("")

    lines += ["## Exploitation", ""]
    if kev.get("in_kev"):
        lines.append(f"- **CISA KEV** since {kev.get('date_added')} (due {kev.get('due_date')}); "
                     f"ransomware use: {md(kev.get('ransomware_use'))}")
    lines += [f"- {md(e['source'])}: {md(e['detail'])} — {link('source', e.get('url'))}" for e in d["exploitation"]]
    if not d["exploitation"]:
        lines.append("- No exploitation evidence collected.")
    lines.append("")

    lines += ["## Public Exploits & PoCs", ""]
    for e in d["public_exploits"] + d["pocs"]:
        lines.append(f"- [{e['kind']}] {link(e['title'], e['url'])} ({md(e['source']['name'])})")
    if not (d["public_exploits"] or d["pocs"]):
        lines.append("- None found.")
    lines += ["", "> PoC code is unverified. Never run it outside an isolated lab.", ""]

    lines += ["## Threat Actors & Campaigns", ""]
    for a in d["threat_actors"] + d["campaigns"] + d["malware"]:
        ev = a["evidence"][0] if a["evidence"] else None
        lines.append(f"- {md(a['name'])} ({a['type']}, {a.get('external_id') or ''})"
                     + (f" — co-mentioned in {link(ev['title'], ev['url'])}" if ev else ""))
    if not (d["threat_actors"] or d["campaigns"] or d["malware"]):
        lines.append("- No association found in collected reports.")
    lines.append("")

    lines += ["## MITRE ATT&CK", ""]
    for t in d["attack"]:
        tactics = ", ".join(x["name"] for x in t["tactics"])
        lines.append(f"- **{t['external_id']} {md(t['name'])}** ({md(tactics)}) — mapping: {t['mapping']['method']}")
    if not d["attack"]:
        lines.append("- No technique mapping.")
    lines.append("")

    lines += ["## Detection", ""]
    for t in d["attack"]:
        for s in t["detection_strategies"][:3]:
            lines.append(f"- {t['external_id']}: {link(s['name'], s['url'])}")
            for a in s["analytics"][:2]:
                srcs = "; ".join(filter(None, (f"{ls.get('name')} {ls.get('channel') or ''}".strip()
                                               for ls in a["log_sources"][:4])))
                lines.append(f"  - {', '.join(a['platforms'])}: {md(srcs)}")
    lines += ["- Sigma / YARA: planned for Phase 2.", ""]

    lines += ["## Mitigation", ""]
    if kev.get("required_action"):
        lines.append(f"- CISA required action: {md(kev['required_action'])}")
    for a in d["vendor_advisories"][:20]:
        lines.append(f"- {link(a.get('title') or a['url'], a['url'])}")
    for t in d["attack"]:
        for m in t["mitigations"][:3]:
            lines.append(f"- {m['external_id']} {md(m['name'])} (for {t['external_id']})")
    lines.append("")

    lines += ["## Timeline", ""]
    lines += [f"- {ev['date'][:10]} — {ev['kind']}: {link(ev['title'], ev.get('url'))} ({md(ev['source'])})"
              for ev in d["timeline"]]
    lines += ["", "## Sources", ""]
    lines += [f"- [Tier {s['tier']}] {md(s['source'])} — {link(s.get('title') or s['url'], s['url'])}"
              for s in d["sources"]]
    lines += ["", "_Generated by Asber. Every statement links to its original source._", ""]
    return "\n".join(lines)
