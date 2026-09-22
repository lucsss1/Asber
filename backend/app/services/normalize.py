"""Source payload → unified model transformations (pure functions, easy to test)."""
from __future__ import annotations

import re
from typing import Any

from app.services.sanitize import clip, html_to_text, parse_date, parse_dt, safe_url

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
URL_IN_TEXT_RE = re.compile(r"https?://[^\s;<>\"']+")


class MalformedRecord(ValueError):
    pass


def valid_cve_id(value: Any) -> str:
    if not isinstance(value, str):
        raise MalformedRecord(f"invalid CVE id: {value!r}")
    value = value.strip().upper()
    if not CVE_ID_RE.match(value):
        raise MalformedRecord(f"invalid CVE id: {value!r}")
    return value


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------
def parse_kev_entry(row: dict) -> dict:
    if not isinstance(row, dict):
        raise MalformedRecord("KEV entry is not an object")
    cve_id = valid_cve_id(row.get("cveID"))
    notes = html_to_text(row.get("notes"), 4000)
    note_urls = [u for u in (safe_url(x.rstrip(".,)")) for x in URL_IN_TEXT_RE.findall(notes)) if u]
    cwes = [c for c in (row.get("cwes") or []) if isinstance(c, str) and c.startswith("CWE-")]
    return {
        "cve_id": cve_id,
        "vendor": clip(html_to_text(row.get("vendorProject")), 200),
        "product": clip(html_to_text(row.get("product")), 300),
        "kev_name": html_to_text(row.get("vulnerabilityName"), 500) or None,
        "kev_date_added": parse_date(row.get("dateAdded")),
        "kev_due_date": parse_date(row.get("dueDate")),
        "kev_required_action": html_to_text(row.get("requiredAction"), 2000) or None,
        "kev_ransomware": clip(row.get("knownRansomwareCampaignUse"), 16),
        "kev_notes": notes or None,
        "short_description": html_to_text(row.get("shortDescription"), 4000) or None,
        "cwes": cwes,
        "note_urls": list(dict.fromkeys(note_urls)),
    }


# ---------------------------------------------------------------------------
# NVD CVE API 2.0
# ---------------------------------------------------------------------------
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


NVD_SOURCE = "nvd@nist.gov"


def _cvss_rank(entry: dict) -> tuple:
    """Lower is better. NVD's own score wins, then any "Primary" score.

    NVD does not always mark its own metric as Primary (e.g. CVE-2020-1472 has two
    "Secondary" v3.1 entries: Microsoft's 5.5 and NVD's 10.0), so type alone is not
    enough to avoid reporting a CNA's much lower score as the severity.
    """
    return (entry.get("source") != NVD_SOURCE, entry.get("type") != "Primary")


def _pick_cvss(metrics: dict) -> dict:
    for key in _CVSS_KEYS:
        entries = [e for e in (metrics.get(key) or []) if isinstance(e, dict)]
        if not entries:
            continue
        entry = min(entries, key=_cvss_rank)
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return {
            "cvss_score": float(score) if isinstance(score, (int, float)) else None,
            "cvss_severity": (severity or "").upper() or None,
            "cvss_vector": clip(data.get("vectorString"), 200),
            "cvss_version": clip(str(data.get("version") or ""), 8),
        }
    return {"cvss_score": None, "cvss_severity": None, "cvss_vector": None, "cvss_version": None}


def _pick_ssvc(metrics: dict) -> dict:
    out = {"ssvc_exploitation": None, "ssvc_automatable": None, "ssvc_technical_impact": None}
    for entry in metrics.get("ssvcV203") or metrics.get("ssvc") or []:
        for opt in (entry.get("ssvcData") or {}).get("options") or []:
            if not isinstance(opt, dict):
                continue
            if "exploitation" in opt:
                out["ssvc_exploitation"] = clip(str(opt["exploitation"]).lower(), 16)
            if "automatable" in opt:
                out["ssvc_automatable"] = clip(str(opt["automatable"]).lower(), 8)
            if "technicalImpact" in opt:
                out["ssvc_technical_impact"] = clip(str(opt["technicalImpact"]).lower(), 16)
    return out


def _cpe_vendor_product(criteria: str) -> tuple[str, str]:
    parts = criteria.split(":")
    if len(parts) > 5:
        return parts[3].replace("_", " "), parts[4].replace("_", " ")
    return "", ""


def parse_nvd_cve(cve: dict) -> dict:
    if not isinstance(cve, dict):
        raise MalformedRecord("NVD item is not an object")
    cve_id = valid_cve_id(cve.get("id"))
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None)
    metrics = cve.get("metrics") or {}

    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value")
            if isinstance(val, str) and val.startswith("CWE-") and val not in cwes:
                cwes.append(val)

    products: dict[tuple[str, str, str], dict] = {}
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable") or not isinstance(m.get("criteria"), str):
                    continue
                vendor, product = _cpe_vendor_product(m["criteria"])
                rng = " ".join(
                    f"{label} {m[k]}" for k, label in (
                        ("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
                        ("versionEndIncluding", "<="), ("versionEndExcluding", "<"))
                    if m.get(k)
                )
                key = (vendor[:200], product[:300], m["criteria"][:400])
                products[key] = {"vendor": key[0], "product": key[1], "cpe": key[2], "versions": rng or None}
    for aff in cve.get("affected") or []:
        for item in aff.get("affectedData") or []:
            vendor = clip(html_to_text(item.get("vendor")), 200) or ""
            product = clip(html_to_text(item.get("product")), 300) or ""
            if not (vendor or product):
                continue
            versions = ", ".join(
                str(v.get("version")) for v in item.get("versions") or []
                if isinstance(v, dict) and v.get("status") == "affected" and v.get("version")
            )[:1000]
            products.setdefault((vendor, product, ""), {"vendor": vendor, "product": product, "cpe": "",
                                                        "versions": versions or None})

    references = []
    for ref in cve.get("references") or []:
        url = safe_url(ref.get("url"))
        if not url:
            continue
        tags = [t for t in ref.get("tags") or [] if isinstance(t, str)]
        if "Exploit" in tags:
            ref_type = "exploit"
        elif "Vendor Advisory" in tags:
            ref_type = "vendor_advisory"
        elif "Patch" in tags:
            ref_type = "patch"
        elif "Mitigation" in tags:
            ref_type = "mitigation"
        else:
            ref_type = "reference"
        references.append({"url": url, "tags": tags, "ref_type": ref_type})

    first = next(iter(products.values()), None)
    return {
        "cve_id": cve_id,
        "description": html_to_text(desc, 8000) or None,
        "vuln_status": clip(cve.get("vulnStatus"), 64),
        "published": parse_dt(cve.get("published")),
        "last_modified": parse_dt(cve.get("lastModified")),
        "cwes": cwes,
        "products": list(products.values()),
        "references": references,
        "primary_vendor": first["vendor"] if first else None,
        "primary_product": first["product"] if first else None,
        **_pick_cvss(metrics),
        **_pick_ssvc(metrics),
    }
