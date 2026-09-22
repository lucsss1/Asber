"""Read-model builders shared by the API and the exporters."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion.registry import REGISTRY_BY_KEY
from app.models import (
    AffectedProduct,
    AttackObject,
    AttackRelationship,
    Document,
    EntityLink,
    Exploit,
    SourceReference,
    Vulnerability,
)
from app.services import correlation, extract
from app.services.correlation import HEURISTIC_TECHNIQUES
from app.services.sanitize import aware

TIER_LABELS = {
    1: "Tier 1 — Government / vendor / original researcher",
    2: "Tier 2 — Major security research organisation",
    3: "Tier 3 — Security news",
    4: "Tier 4 — Community / unverified",
}


def iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return aware(value).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def source_info(key: str) -> dict:
    s = REGISTRY_BY_KEY.get(key)
    if not s:
        return {"key": key, "name": key, "tier": 4, "source_type": "Unknown"}
    return {"key": key, "name": s.name, "tier": s.tier, "source_type": s.source_type, "homepage": s.homepage}


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------
def vuln_row(v: Vulnerability) -> dict:
    return {
        "cve_id": v.cve_id,
        "title": v.title or v.kev_name,
        "vendor": v.vendor,
        "product": v.product,
        "severity": v.cvss_severity,
        "cvss_score": v.cvss_score,
        "in_kev": v.in_kev,
        "kev_date_added": iso(v.kev_date_added),
        "actively_exploited": v.actively_exploited,
        "has_exploit": v.has_exploit,
        "has_poc": v.has_poc,
        "exploit_count": v.exploit_count,
        "poc_count": v.poc_count,
        "published": iso(v.published),
        "first_seen": iso(v.first_seen),
        "last_updated": iso(v.updated_at),
        "last_activity_at": iso(v.last_activity_at),
        "source_count": v.source_count,
        "tags": v.tags or [],
        "platforms": v.platforms or [],
        "techniques": v.techniques or [],
        "relevance_score": v.relevance_score,
        "relevance_reasons": v.relevance_reasons or [],
    }


def document_row(d: Document, attack_names: list[dict] | None = None, cves: list[str] | None = None) -> dict:
    return {
        "id": d.id,
        "title": d.title,
        "summary": d.summary,
        "url": d.url,
        "doc_type": d.doc_type,
        "source": source_info(d.source_key),
        "tier": d.tier,
        "categories": d.categories or [],
        "authors": d.authors or [],
        "reports_exploitation": d.reports_exploitation,
        "published_at": iso(d.published_at),
        "collected_at": iso(d.collected_at),
        "cves": cves or [],
        "entities": attack_names or [],
    }


def exploit_row(e: Exploit) -> dict:
    return {
        "id": e.id,
        "external_id": e.external_id,
        "title": e.title,
        "description": e.description,
        "url": e.url,
        "kind": e.kind,
        "platform": e.platform,
        "exploit_type": e.exploit_type,
        "author": e.author,
        "verified": e.verified,
        "stars": e.stars,
        "language": e.language,
        "cve_ids": e.cve_ids or [],
        "source": source_info(e.source_key),
        "tier": e.tier,
        "published_at": iso(e.published_at),
        "collected_at": iso(e.collected_at),
        "warning": "Unverified community code. Never run PoCs outside an isolated lab."
        if e.source_key == "github" else None,
    }


def attack_row(a: AttackObject, mentions: int | None = None) -> dict:
    return {
        "stix_id": a.stix_id,
        "external_id": a.external_id,
        "type": a.obj_type,
        "name": a.name,
        "aliases": a.aliases or [],
        "platforms": a.platforms or [],
        "tactics": a.tactics or [],
        "url": a.url,
        "is_subtechnique": a.is_subtechnique,
        "description": (a.description or "")[:400],
        "modified": iso(a.modified),
        "created": iso(a.created),
        "mentions": mentions,
    }


def document_entities(session: Session, doc_ids: list[int]) -> tuple[dict[int, list[dict]], dict[int, list[str]]]:
    """Batch-load extracted entities for a list of documents."""
    if not doc_ids:
        return {}, {}
    rows = session.execute(
        select(EntityLink.subject_id, EntityLink.object_type, EntityLink.object_id)
        .where(EntityLink.subject_type == "document", EntityLink.subject_id.in_([str(i) for i in doc_ids]),
               EntityLink.relation == "mentions")
    ).all()
    stix_ids = {oid for _, ot, oid in rows if ot == "attack"}
    names = {a.stix_id: a for a in session.scalars(select(AttackObject).where(AttackObject.stix_id.in_(stix_ids)))} \
        if stix_ids else {}
    ents: dict[int, list[dict]] = {}
    cves: dict[int, list[str]] = {}
    for sid, ot, oid in rows:
        if ot == "cve":
            cves.setdefault(int(sid), []).append(oid)
        elif ot == "attack" and oid in names:
            a = names[oid]
            ents.setdefault(int(sid), []).append({"stix_id": a.stix_id, "type": a.obj_type, "name": a.name,
                                                  "external_id": a.external_id})
    return ents, cves


# ---------------------------------------------------------------------------
# ATT&CK helpers
# ---------------------------------------------------------------------------
def technique_detail(session: Session, tech: AttackObject) -> dict:
    tactics = session.scalars(select(AttackObject).where(AttackObject.obj_type == "tactic",
                                                         AttackObject.shortname.in_(tech.tactics or []))).all()
    rel_rows = session.execute(
        select(AttackRelationship, AttackObject)
        .join(AttackObject, AttackObject.stix_id == AttackRelationship.source_ref)
        .where(AttackRelationship.target_ref == tech.stix_id,
               AttackRelationship.relationship_type.in_(("detects", "mitigates")))
    ).all()
    strategies, mitigations = [], []
    for rel, obj in rel_rows:
        if rel.relationship_type == "detects" and obj.obj_type == "detection_strategy":
            strategies.append(obj)
        elif rel.relationship_type == "mitigates" and obj.obj_type == "mitigation" and not obj.deprecated:
            mitigations.append({"external_id": obj.external_id, "name": obj.name, "url": obj.url,
                                "how": (rel.description or "")[:400]})
    detection = []
    for strat in strategies:
        analytic_ids = (strat.extra or {}).get("analytic_refs") or []
        analytics = session.scalars(select(AttackObject).where(AttackObject.stix_id.in_(analytic_ids))).all() \
            if analytic_ids else []
        comp_ids = {ls.get("data_component") for a in analytics for ls in (a.extra or {}).get("log_sources", [])}
        comps = {c.stix_id: c.name for c in session.scalars(
            select(AttackObject).where(AttackObject.stix_id.in_([c for c in comp_ids if c])))} if comp_ids else {}
        detection.append({
            "external_id": strat.external_id, "name": strat.name, "url": strat.url,
            "analytics": [{
                "external_id": a.external_id, "platforms": a.platforms or [],
                "description": a.description,
                "log_sources": [{"data_component": comps.get(ls.get("data_component")), "name": ls.get("name"),
                                 "channel": ls.get("channel")} for ls in (a.extra or {}).get("log_sources", [])][:8],
            } for a in analytics][:6],
        })
    return {
        "external_id": tech.external_id, "name": tech.name, "url": tech.url, "stix_id": tech.stix_id,
        "tactics": [{"shortname": t.shortname, "name": t.name, "external_id": t.external_id} for t in tactics],
        "platforms": tech.platforms or [],
        "description": (tech.description or "")[:600],
        "detection_strategies": detection,
        "legacy_detection": (tech.extra or {}).get("detection"),
        "mitigations": mitigations,
    }


def techniques_by_external_ids(session: Session, ids: list[str]) -> dict[str, AttackObject]:
    if not ids:
        return {}
    rows = session.scalars(select(AttackObject).where(AttackObject.obj_type == "technique",
                                                      AttackObject.external_id.in_(ids),
                                                      AttackObject.revoked.is_(False))).all()
    return {r.external_id: r for r in rows}


# ---------------------------------------------------------------------------
# CVE page
# ---------------------------------------------------------------------------
def cve_detail(session: Session, cve_id: str) -> dict | None:
    vuln = session.get(Vulnerability, cve_id)
    links, docs, exploits = correlation.linked_subjects(session, cve_id)
    if vuln is None and not links:
        return None

    doc_links = {int(l.subject_id): l for l in links if l.subject_type == "document" and l.relation == "mentions"}
    focused = {i for i, l in doc_links.items() if l.confidence == "high"}
    exploitation_links = [l for l in links if l.relation == "reports_exploitation"]
    doc_by_id = {d.id: d for d in docs}
    ents, cve_map = document_entities(session, [d.id for d in docs])

    def doc_out(d: Document) -> dict:
        row = document_row(d, ents.get(d.id), cve_map.get(d.id))
        link_ = doc_links.get(d.id)
        row["link"] = {"confidence": link_.confidence, "method": link_.method, "evidence": link_.evidence} \
            if link_ else None
        return row

    docs_sorted = sorted(docs, key=lambda d: aware(d.published_at) or aware(d.collected_at), reverse=True)
    research = [doc_out(d) for d in docs_sorted if d.doc_type in ("research", "repository")]
    news = [doc_out(d) for d in docs_sorted if d.doc_type == "news"]
    advisories_docs = [doc_out(d) for d in docs_sorted if d.doc_type == "advisory"]

    # Actors / campaigns / malware co-mentioned in focused reports
    related: dict[str, dict] = {}
    for a, l in correlation.co_mentioned_attack(session, docs, focused):
        if a.obj_type not in ("group", "campaign", "malware", "tool", "technique"):
            continue
        entry = related.setdefault(a.stix_id, {**attack_row(a), "evidence": []})
        d = doc_by_id.get(int(l.subject_id))
        if d:
            entry["evidence"].append({"document_id": d.id, "title": d.title, "url": d.url,
                                      "source": source_info(d.source_key)["name"], "snippet": l.evidence,
                                      "method": "co-mention in the same report"})
    by_type = lambda *types: [r for r in related.values() if r["type"] in types]  # noqa: E731

    refs = session.scalars(select(SourceReference).where(SourceReference.cve_id == cve_id)).all() if vuln else []
    products = session.scalars(select(AffectedProduct).where(AffectedProduct.cve_id == cve_id)
                               .limit(300)).all() if vuln else []

    # ATT&CK techniques: explicit (from reports) + heuristic (impact-based)
    explicit = {r["external_id"]: r for r in by_type("technique")}
    internet_facing = bool(vuln and extract.INTERNET_FACING.search(
        " ".join(filter(None, [vuln.vendor, vuln.product, vuln.kev_name]))))
    heuristic = dict(correlation.heuristic_techniques(vuln, internet_facing)) if vuln else {}
    tech_objs = techniques_by_external_ids(session, list({*explicit, *heuristic}))
    attack_section = []
    for ext_id, obj in sorted(tech_objs.items()):
        item = technique_detail(session, obj)
        if ext_id in explicit:
            item["mapping"] = {"method": "explicit", "detail": "Technique mentioned in a report about this CVE",
                               "evidence": explicit[ext_id]["evidence"]}
        else:
            item["mapping"] = {"method": "heuristic", "detail": HEURISTIC_TECHNIQUES.get(ext_id, ""),
                               "evidence": []}
        attack_section.append(item)

    public_exploits = [exploit_row(e) for e in exploits if e.kind == "exploit"]
    pocs = [exploit_row(e) for e in exploits if e.kind == "poc"]
    other_repos = [exploit_row(e) for e in exploits if e.kind not in ("exploit", "poc")]

    exploitation = []
    if vuln and vuln.in_kev:
        exploitation.append({"source": "CISA KEV", "tier": 1, "detail": "Listed as known exploited",
                             "date": iso(vuln.kev_date_added), "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})
    if vuln and vuln.ssvc_exploitation:
        exploitation.append({"source": "CISA SSVC (via NVD)", "tier": 1,
                             "detail": f"SSVC exploitation = {vuln.ssvc_exploitation}; automatable = "
                                       f"{vuln.ssvc_automatable}; technical impact = {vuln.ssvc_technical_impact}",
                             "date": None, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
    for l in exploitation_links:
        d = doc_by_id.get(int(l.subject_id))
        if d:
            exploitation.append({"source": source_info(d.source_key)["name"], "tier": d.tier,
                                 "detail": l.evidence, "date": iso(d.published_at), "url": d.url,
                                 "confidence": l.confidence})

    vendor_advisories = [{"url": r.url, "title": r.title, "tags": r.tags, "source": source_info(r.source_key)["name"]}
                         for r in refs if r.ref_type in ("vendor_advisory", "patch", "mitigation")]

    timeline = build_timeline(vuln, docs, exploits)

    sources = []
    for r in refs:
        info = source_info(r.source_key)
        sources.append({"url": r.url, "title": r.title, "ref_type": r.ref_type, "tags": r.tags,
                        "source": info["name"], "source_type": info["source_type"], "tier": info["tier"],
                        "published": iso(r.published_at), "collected": iso(r.collected_at)})
    for d in docs_sorted:
        info = source_info(d.source_key)
        sources.append({"url": d.url, "title": d.title, "ref_type": d.doc_type, "tags": d.categories[:5],
                        "source": info["name"], "source_type": info["source_type"], "tier": d.tier,
                        "published": iso(d.published_at), "collected": iso(d.collected_at)})
    for e in exploits:
        info = source_info(e.source_key)
        sources.append({"url": e.url, "title": e.title, "ref_type": e.kind, "tags": [],
                        "source": info["name"], "source_type": info["source_type"], "tier": e.tier,
                        "published": iso(e.published_at), "collected": iso(e.collected_at)})
    sources.sort(key=lambda s: (s["tier"], s["source"]))

    overview = vuln_row(vuln) if vuln else {"cve_id": cve_id, "title": None, "relevance_score": 0,
                                            "relevance_reasons": []}
    if vuln:
        overview.update({
            "description": vuln.description, "vuln_status": vuln.vuln_status, "cwes": vuln.cwes or [],
            "last_modified": iso(vuln.last_modified), "nvd_fetched_at": iso(vuln.nvd_fetched_at),
        })
    return {
        "cve_id": cve_id,
        "tracked": vuln is not None,
        "overview": overview,
        "risk": {
            "relevance_score": overview.get("relevance_score", 0),
            "reasons": overview.get("relevance_reasons", []),
            "note": "Threat Relevance is an internal prioritisation score, not a replacement for CVSS.",
        },
        "cvss": {"score": vuln.cvss_score, "severity": vuln.cvss_severity, "vector": vuln.cvss_vector,
                 "version": vuln.cvss_version} if vuln else None,
        "ssvc": {"exploitation": vuln.ssvc_exploitation, "automatable": vuln.ssvc_automatable,
                 "technical_impact": vuln.ssvc_technical_impact} if vuln else None,
        "kev": {"in_kev": vuln.in_kev, "name": vuln.kev_name, "date_added": iso(vuln.kev_date_added),
                "due_date": iso(vuln.kev_due_date), "required_action": vuln.kev_required_action,
                "ransomware_use": vuln.kev_ransomware, "notes": vuln.kev_notes} if vuln else None,
        "affected_products": [{"vendor": p.vendor, "product": p.product, "cpe": p.cpe or None,
                               "versions": p.versions, "source": source_info(p.source_key)["name"]}
                              for p in products],
        "exploitation": exploitation,
        "public_exploits": public_exploits,
        "pocs": pocs,
        "other_repositories": other_repos,
        "threat_actors": by_type("group"),
        "campaigns": by_type("campaign"),
        "malware": by_type("malware", "tool"),
        "attack": attack_section,
        "detection": {
            "attack_detection_strategies": sum(len(t["detection_strategies"]) for t in attack_section),
            "sigma": {"status": "phase_2", "items": []},
            "yara": {"status": "phase_2", "items": []},
            "detection_repositories": [r for r in other_repos if r["kind"] == "detection"],
        },
        "vendor_advisories": vendor_advisories + advisories_docs,
        "research": research,
        "news": news,
        "timeline": timeline,
        "sources": sources,
    }


def build_timeline(vuln: Vulnerability | None, docs: list[Document], exploits: list[Exploit]) -> list[dict]:
    events: list[dict] = []

    def add(when, kind, title, source, url=None):
        if when:
            events.append({"date": iso(when), "kind": kind, "title": title, "source": source, "url": url})

    if vuln:
        add(vuln.published, "cve_published", "CVE published", "NVD",
            f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}")
        add(correlation.aware_date(vuln.kev_date_added), "kev_added", "Added to CISA KEV", "CISA KEV",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        add(correlation.aware_date(vuln.kev_due_date), "remediation_due", "CISA remediation due date", "CISA KEV")
        add(vuln.first_seen, "collected", "First collected by this dashboard", "Asber")
    kind_map = {"research": "research", "news": "news", "advisory": "vendor_advisory", "repository": "research"}
    for d in docs:
        add(d.published_at or d.collected_at, kind_map.get(d.doc_type, "news"), d.title,
            source_info(d.source_key)["name"], d.url)
    for e in exploits:
        kind = {"exploit": "exploit", "poc": "poc", "detection": "detection_rule"}.get(e.kind, "repository")
        add(e.published_at or e.collected_at, kind, e.title, source_info(e.source_key)["name"], e.url)
    events.sort(key=lambda ev: ev["date"])
    return events
