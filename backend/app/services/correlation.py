"""Correlation engine.

* ``link``                     – idempotent creation of an explainable edge.
* ``process_document``         – extract entities from an article and link them.
* ``upsert_vulnerability_*``   – merge data from KEV / NVD into the canonical CVE.
* ``recompute_vulnerability``  – derive flags, tags and the Threat Relevance Score.
* ``heuristic_techniques``     – impact-based ATT&CK suggestions (clearly labelled).
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion.registry import REGISTRY_BY_KEY
from app.models import (
    AffectedProduct,
    AttackObject,
    Document,
    EntityLink,
    Exploit,
    SourceReference,
    Vulnerability,
    utcnow,
)
from app.services import extract
from app.services.sanitize import aware
from app.services.scoring import ScoreInput, compute_relevance

log = logging.getLogger("asber.correlation")

MAX_CVES_FOR_STRONG_LINK = 5  # an article listing 40 CVEs is a roundup, not a focused report

HEURISTIC_TECHNIQUES = {
    # (condition, technique, rationale)
    "T1190": "Internet-facing product with RCE / auth-bypass impact → Exploit Public-Facing Application",
    "T1068": "Privilege-escalation impact → Exploitation for Privilege Escalation",
    "T1203": "Client-side code execution (browser/document/app) → Exploitation for Client Execution",
    "T1212": "Credential exposure/bypass → Exploitation for Credential Access",
    "T1211": "Security feature bypass → Exploitation for Defense Evasion",
    "T1210": "Network service RCE on internal protocol → Exploitation of Remote Services",
}


def source_name(key: str) -> str:
    s = REGISTRY_BY_KEY.get(key)
    return s.name if s else key


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------
def link(
    session: Session, *, subject_type: str, subject_id: str | int, object_type: str, object_id: str,
    relation: str, method: str, source_key: str, confidence: str = "medium",
    evidence: str | None = None, observed_at: datetime | None = None,
) -> tuple[EntityLink, bool]:
    subject_id = str(subject_id)
    existing = session.scalar(
        select(EntityLink).where(
            EntityLink.subject_type == subject_type, EntityLink.subject_id == subject_id,
            EntityLink.object_type == object_type, EntityLink.object_id == object_id,
            EntityLink.relation == relation,
        )
    )
    if existing:
        return existing, False
    edge = EntityLink(subject_type=subject_type, subject_id=subject_id, object_type=object_type,
                      object_id=object_id, relation=relation, method=method, confidence=confidence,
                      source_key=source_key, evidence=(evidence or "")[:500] or None, observed_at=observed_at)
    session.add(edge)
    return edge, True


def process_document(session: Session, doc: Document, full_text: str,
                     dictionary: extract.AttackDictionary | None = None) -> set[str]:
    """Extract CVEs / ATT&CK entities from a document and link them. Returns touched CVE ids."""
    session.flush()  # ensure doc.id
    dictionary = dictionary or extract.get_attack_dictionary(session)
    text = f"{doc.title}\n{full_text}"
    cves = extract.find_cves(text)
    focused = len(cves) <= MAX_CVES_FOR_STRONG_LINK
    reports_exploitation = bool(extract.EXPLOITATION_PHRASES.search(text))
    doc.reports_exploitation = reports_exploitation

    for cve in cves:
        link(session, subject_type="document", subject_id=doc.id, object_type="cve", object_id=cve,
             relation="mentions", method="regex", source_key=doc.source_key,
             confidence="high" if focused else "low", evidence=extract.snippet(text, cve),
             observed_at=doc.published_at)
        if reports_exploitation and focused:
            phrase = extract.EXPLOITATION_PHRASES.search(text).group(0)
            link(session, subject_type="document", subject_id=doc.id, object_type="cve", object_id=cve,
                 relation="reports_exploitation", method="regex", source_key=doc.source_key,
                 confidence="medium", evidence=extract.snippet(text, phrase), observed_at=doc.published_at)

    for tech in extract.find_techniques(text):
        stix_id = dictionary.technique_ids.get(tech)
        if stix_id:
            link(session, subject_type="document", subject_id=doc.id, object_type="attack", object_id=stix_id,
                 relation="mentions", method="regex", source_key=doc.source_key, confidence="high",
                 evidence=extract.snippet(text, tech), observed_at=doc.published_at)

    for stix_id, _obj_type, _name, matched in dictionary.find(text):
        link(session, subject_type="document", subject_id=doc.id, object_type="attack", object_id=stix_id,
             relation="mentions", method="dictionary", source_key=doc.source_key, confidence="medium",
             evidence=extract.snippet(text, matched), observed_at=doc.published_at)

    doc.extraction_version = dictionary.version
    return set(cves)


# ---------------------------------------------------------------------------
# Vulnerability upserts
# ---------------------------------------------------------------------------
def get_or_create_vulnerability(session: Session, cve_id: str) -> tuple[Vulnerability, bool]:
    vuln = session.get(Vulnerability, cve_id)
    if vuln:
        return vuln, False
    vuln = Vulnerability(cve_id=cve_id, first_seen=utcnow(), updated_at=utcnow(), cwes=[], tags=[],
                         platforms=[], relevance_reasons=[])
    session.add(vuln)
    return vuln, True


def _assign(obj, values: dict) -> bool:
    changed = False
    for key, value in values.items():
        if getattr(obj, key) != value:
            setattr(obj, key, value)
            changed = True
    return changed


def add_reference(session: Session, cve_id: str, source_key: str, url: str, ref_type: str,
                  title: str | None = None, tags: list | None = None, published_at=None) -> bool:
    exists = session.scalar(select(SourceReference.id).where(SourceReference.cve_id == cve_id,
                                                             SourceReference.url == url))
    if exists:
        return False
    session.add(SourceReference(cve_id=cve_id, source_key=source_key, url=url, ref_type=ref_type,
                                title=title, tags=tags or [], published_at=published_at))
    return True


def apply_kev(session: Session, data: dict) -> tuple[bool, bool]:
    """Merge a parsed KEV entry. Returns (created, changed)."""
    vuln, created = get_or_create_vulnerability(session, data["cve_id"])
    values = {k: data[k] for k in ("kev_name", "kev_date_added", "kev_due_date", "kev_required_action",
                                   "kev_ransomware", "kev_notes")}
    values["in_kev"] = True
    if not vuln.title:
        values["title"] = data["kev_name"]
    if not vuln.description and data["short_description"]:
        values["description"] = data["short_description"]
    if not vuln.vendor:
        values["vendor"] = data["vendor"]
    if not vuln.product:
        values["product"] = data["product"]
    if data["cwes"] and not vuln.cwes:
        values["cwes"] = data["cwes"]
    changed = _assign(vuln, values)
    if created or changed:
        vuln.updated_at = utcnow()
    session.flush()
    add_reference(session, vuln.cve_id, "cisa_kev",
                  f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={vuln.cve_id}",
                  "kev", title=f"CISA KEV: {data['kev_name'] or vuln.cve_id}",
                  published_at=aware_date(data["kev_date_added"]))
    if data["vendor"] or data["product"]:
        _ensure_product(session, vuln.cve_id, data["vendor"] or "", data["product"] or "", "", None, "cisa_kev")
    for url in data["note_urls"]:
        if "cisa.gov/news-events/directives" in url or "nvd.nist.gov" in url:
            continue
        add_reference(session, vuln.cve_id, "cisa_kev", url, "vendor_advisory", title="Vendor advisory (via CISA KEV notes)")
    return created, changed


def apply_nvd(session: Session, data: dict, track_new: bool = True) -> tuple[bool, bool]:
    vuln = session.get(Vulnerability, data["cve_id"])
    if vuln is None and not track_new:
        return False, False
    vuln, created = get_or_create_vulnerability(session, data["cve_id"])
    values = {k: data[k] for k in ("vuln_status", "published", "last_modified", "cvss_score", "cvss_severity",
                                   "cvss_vector", "cvss_version", "ssvc_exploitation", "ssvc_automatable",
                                   "ssvc_technical_impact")}
    if data["description"]:
        values["description"] = data["description"]
    if data["cwes"]:
        values["cwes"] = data["cwes"]
    if not vuln.vendor and data["primary_vendor"]:
        values["vendor"] = data["primary_vendor"][:200]
    if not vuln.product and data["primary_product"]:
        values["product"] = data["primary_product"][:300]
    if not vuln.title and data["description"]:
        values["title"] = data["description"][:140]
    # compare datetimes safely (SQLite drops tzinfo)
    for k in ("published", "last_modified"):
        if aware(getattr(vuln, k)) == values[k]:
            values.pop(k)
    changed = _assign(vuln, values)
    vuln.nvd_fetched_at = utcnow()
    if created or changed:
        vuln.updated_at = utcnow()
    session.flush()
    add_reference(session, vuln.cve_id, "nvd", f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}", "nvd",
                  title=f"NVD: {vuln.cve_id}", published_at=data["published"])
    add_reference(session, vuln.cve_id, "cve_org", f"https://www.cve.org/CVERecord?id={vuln.cve_id}", "cve_org",
                  title=f"CVE Record: {vuln.cve_id}", published_at=data["published"])
    seen = set()
    for ref in data["references"]:
        if ref["url"] in seen:
            continue
        seen.add(ref["url"])
        add_reference(session, vuln.cve_id, "nvd", ref["url"], ref["ref_type"], tags=ref["tags"])
    for p in data["products"][:500]:
        _ensure_product(session, vuln.cve_id, p["vendor"], p["product"], p["cpe"], p["versions"], "nvd")
    return created, changed


def aware_date(d: date | None) -> datetime | None:
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc) if d else None


def _ensure_product(session, cve_id, vendor, product, cpe, versions, source_key):
    exists = session.scalar(select(AffectedProduct.id).where(
        AffectedProduct.cve_id == cve_id, AffectedProduct.vendor == vendor,
        AffectedProduct.product == product, AffectedProduct.cpe == cpe))
    if not exists:
        session.add(AffectedProduct(cve_id=cve_id, vendor=vendor, product=product, cpe=cpe, versions=versions,
                                    source_key=source_key))


# ---------------------------------------------------------------------------
# Derived fields & score
# ---------------------------------------------------------------------------
def linked_subjects(session: Session, cve_id: str) -> tuple[list[EntityLink], list[Document], list[Exploit]]:
    links = session.scalars(select(EntityLink).where(EntityLink.object_type == "cve",
                                                     EntityLink.object_id == cve_id)).all()
    doc_ids = {int(l.subject_id) for l in links if l.subject_type == "document"}
    exp_ids = {int(l.subject_id) for l in links if l.subject_type == "exploit"}
    docs = session.scalars(select(Document).where(Document.id.in_(doc_ids))).all() if doc_ids else []
    exps = session.scalars(select(Exploit).where(Exploit.id.in_(exp_ids))).all() if exp_ids else []
    return list(links), list(docs), list(exps)


def co_mentioned_attack(session: Session, docs: Iterable[Document], focused_doc_ids: set[int]) -> list[tuple[AttackObject, EntityLink]]:
    ids = [str(d.id) for d in docs if d.id in focused_doc_ids]
    if not ids:
        return []
    rows = session.execute(
        select(AttackObject, EntityLink)
        .join(EntityLink, EntityLink.object_id == AttackObject.stix_id)
        .where(EntityLink.subject_type == "document", EntityLink.subject_id.in_(ids),
               EntityLink.object_type == "attack")
    ).all()
    return [(a, l) for a, l in rows]


def heuristic_techniques(vuln: Vulnerability, internet_facing: bool) -> list[tuple[str, str]]:
    text = " ".join(filter(None, [vuln.title, vuln.description, vuln.kev_name])).lower()
    tags = set(vuln.tags or [])
    out: list[tuple[str, str]] = []
    if internet_facing and tags & {"rce", "auth_bypass", "sqli", "path_traversal"}:
        out.append(("T1190", HEURISTIC_TECHNIQUES["T1190"]))
    if "privilege_escalation" in tags:
        out.append(("T1068", HEURISTIC_TECHNIQUES["T1068"]))
    if "rce" in tags and not internet_facing and any(
            k in text for k in ("browser", "chrome", "webkit", "office", "word", "excel", "reader", "document",
                                "file", "outlook", "mail client")):
        out.append(("T1203", HEURISTIC_TECHNIQUES["T1203"]))
    if any(k in text for k in ("credential", "password", "ntlm hash", "token")) and tags & {"auth_bypass", "info_disclosure"}:
        out.append(("T1212", HEURISTIC_TECHNIQUES["T1212"]))
    if "security feature bypass" in text or "mark of the web" in text or "smartscreen" in text:
        out.append(("T1211", HEURISTIC_TECHNIQUES["T1211"]))
    if "rce" in tags and not internet_facing and any(k in text for k in ("smb", "rdp", "rpc", "remote desktop")):
        out.append(("T1210", HEURISTIC_TECHNIQUES["T1210"]))
    return out


def recompute_vulnerability(session: Session, cve_id: str, now: datetime | None = None) -> Vulnerability | None:
    vuln = session.get(Vulnerability, cve_id)
    if vuln is None:
        return None
    session.flush()
    links, docs, exploits = linked_subjects(session, cve_id)

    public_exploits = [e for e in exploits if e.kind == "exploit"]
    pocs = [e for e in exploits if e.kind == "poc"]
    focused = {int(l.subject_id) for l in links if l.subject_type == "document" and l.relation == "mentions"
               and l.confidence == "high"}

    evidence: list[str] = []
    if vuln.in_kev:
        evidence.append("CISA KEV")
    if vuln.ssvc_exploitation == "active":
        evidence.append("CISA SSVC (via NVD)")
    doc_by_id = {d.id: d for d in docs}
    for l in links:
        if l.relation == "reports_exploitation" and l.subject_type == "document":
            evidence.append(source_name(doc_by_id[int(l.subject_id)].source_key) if int(l.subject_id) in doc_by_id
                            else source_name(l.source_key))

    attack = co_mentioned_attack(session, docs, focused)
    actors = sorted({a.name for a, _ in attack if a.obj_type in ("group", "campaign")})

    ransomware = (vuln.kev_ransomware or "").lower() == "known" or any(
        extract.RANSOMWARE_RE.search(f"{d.title} {d.summary or ''}") for d in docs if d.id in focused)

    blob = " ".join(filter(None, [vuln.title, vuln.kev_name, vuln.description]))
    product_blob = " ".join(filter(None, [vuln.vendor, vuln.product, vuln.kev_name]))
    vuln.tags = extract.classify_impact(blob, vuln.cwes or [])
    vuln.platforms = extract.classify_platforms(f"{product_blob} {blob}")
    internet_facing = bool(extract.INTERNET_FACING.search(product_blob))

    refs_sources = set(session.scalars(select(SourceReference.source_key)
                                       .where(SourceReference.cve_id == cve_id)).all())
    refs_sources.discard("cve_org")  # CVE.org mirrors the CNA record; not independent of NVD
    independent = refs_sources | {d.source_key for d in docs} | {e.source_key for e in exploits}
    product_count = len(session.scalars(select(AffectedProduct.id).where(AffectedProduct.cve_id == cve_id)).all())

    signals = [aware(vuln.published), aware_date(vuln.kev_date_added)]
    signals += [aware(d.published_at) for d in docs] + [aware(e.published_at) for e in exploits]
    signals = [s for s in signals if s]

    result = compute_relevance(ScoreInput(
        in_kev=vuln.in_kev,
        active_exploitation_evidence=evidence,
        ransomware=ransomware,
        exploit_count=len(public_exploits),
        poc_count=len(pocs),
        ssvc_poc=vuln.ssvc_exploitation == "poc",
        threat_actors=actors,
        tags=vuln.tags,
        internet_facing=internet_facing,
        cvss_score=vuln.cvss_score,
        independent_sources=len(independent),
        most_recent_signal=max(signals) if signals else None,
        affected_product_count=product_count,
    ), now=now)

    vuln.actively_exploited = bool(evidence)
    vuln.exploit_count = len(public_exploits)
    vuln.poc_count = len(pocs)
    vuln.has_exploit = bool(public_exploits)
    vuln.has_poc = bool(pocs) or vuln.ssvc_exploitation == "poc"
    vuln.source_count = len(independent)
    vuln.relevance_score = result.score
    vuln.relevance_reasons = result.reasons
    vuln.last_activity_at = max(signals) if signals else None

    techniques = {a.external_id: "explicit" for a, _ in attack if a.obj_type == "technique" and a.external_id}
    for tech_id, _why in heuristic_techniques(vuln, internet_facing):
        techniques.setdefault(tech_id, "heuristic")
    vuln.techniques = [{"id": k, "method": v} for k, v in sorted(techniques.items())]
    return vuln


def recompute_many(session: Session, cve_ids: Iterable[str]) -> int:
    ids = sorted(set(cve_ids))
    n = 0
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for cve_id in session.scalars(select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(chunk))).all():
            recompute_vulnerability(session, cve_id)
            n += 1
    return n
