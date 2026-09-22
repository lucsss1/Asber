"""MITRE ATT&CK endpoints (tactics matrix, entity lists, entity detail)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.common import Page, like_term, paginate
from app.api.vulnerabilities import cves_mentioned_with, resolve_attack
from app.db import get_db
from app.models import AttackObject, AttackRelationship, Document, EntityLink, Vulnerability
from app.services.views import attack_row, document_row, technique_detail, vuln_row

router = APIRouter(prefix="/api/attack", tags=["attack"])

LISTABLE = {"technique", "group", "malware", "tool", "campaign", "mitigation", "tactic",
            "detection_strategy", "data_component"}


def mention_counts(session: Session, stix_ids: list[str] | None = None) -> dict[str, int]:
    stmt = (select(EntityLink.object_id, func.count(func.distinct(EntityLink.subject_id)))
            .where(EntityLink.object_type == "attack", EntityLink.relation == "mentions")
            .group_by(EntityLink.object_id))
    if stix_ids:
        stmt = stmt.where(EntityLink.object_id.in_(stix_ids))
    return dict(session.execute(stmt).all())


@router.get("/tactics")
def tactics(session: Session = Depends(get_db)):
    rows = session.scalars(select(AttackObject).where(AttackObject.obj_type == "tactic",
                                                      AttackObject.deprecated.is_(False))).all()
    rows.sort(key=lambda t: (t.extra or {}).get("order", 99))
    techniques = session.scalars(select(AttackObject).where(AttackObject.obj_type == "technique",
                                                            AttackObject.revoked.is_(False),
                                                            AttackObject.deprecated.is_(False),
                                                            AttackObject.is_subtechnique.is_(False))).all()
    counts = mention_counts(session)
    out = []
    for tactic in rows:
        techs = [t for t in techniques if tactic.shortname in (t.tactics or [])]
        techs.sort(key=lambda t: (-counts.get(t.stix_id, 0), t.external_id or ""))
        out.append({
            "external_id": tactic.external_id, "name": tactic.name, "shortname": tactic.shortname,
            "url": tactic.url, "description": (tactic.description or "")[:300],
            "technique_count": len(techs),
            "techniques": [attack_row(t, counts.get(t.stix_id, 0)) for t in techs],
        })
    return {"tactics": out, "mentioned_total": sum(counts.values())}


@router.get("/objects")
def list_objects(
    session: Session = Depends(get_db),
    page: Page = Depends(),
    type: str = Query("group"),
    q: str | None = None,
    mentioned: bool = False,
    sort: str = "mentions",
):
    if type not in LISTABLE:
        raise HTTPException(400, f"type must be one of {sorted(LISTABLE)}")
    stmt = select(AttackObject).where(AttackObject.obj_type == type, AttackObject.revoked.is_(False),
                                      AttackObject.deprecated.is_(False))
    if q:
        term = like_term(q)
        stmt = stmt.where(or_(AttackObject.name.ilike(term), AttackObject.external_id.ilike(term),
                              AttackObject.description.ilike(term)))
    if mentioned:
        mentioned_ids = select(EntityLink.object_id).where(EntityLink.object_type == "attack")
        stmt = stmt.where(AttackObject.stix_id.in_(mentioned_ids))
    if sort == "name":
        result = paginate(session, stmt.order_by(AttackObject.name), page, lambda a: a)
    else:
        result = paginate(session, stmt.order_by(AttackObject.modified.desc().nullslast()), page, lambda a: a)
    counts = mention_counts(session, [a.stix_id for a in result["items"]])
    rows = [attack_row(a, counts.get(a.stix_id, 0)) for a in result["items"]]
    if sort == "mentions":
        rows.sort(key=lambda r: (-(r["mentions"] or 0), r["name"]))
    result["items"] = rows
    return result


@router.get("/objects/{identifier}")
def get_object(identifier: str, session: Session = Depends(get_db)):
    obj = resolve_attack(session, identifier)
    if obj is None:
        raise HTTPException(404, f"unknown ATT&CK object: {identifier}")
    data = attack_row(obj)
    data["description"] = obj.description
    data["extra"] = obj.extra or {}

    # Relationships in both directions, resolved to names
    rels = session.execute(
        select(AttackRelationship).where(or_(AttackRelationship.source_ref == obj.stix_id,
                                             AttackRelationship.target_ref == obj.stix_id))).scalars().all()
    other_ids = {r.target_ref if r.source_ref == obj.stix_id else r.source_ref for r in rels}
    others = {a.stix_id: a for a in session.scalars(select(AttackObject).where(
        AttackObject.stix_id.in_(other_ids)))} if other_ids else {}
    grouped: dict[str, list[dict]] = {}
    for r in rels:
        outgoing = r.source_ref == obj.stix_id
        other = others.get(r.target_ref if outgoing else r.source_ref)
        if other is None or other.revoked:
            continue
        label = f"{'uses' if outgoing else 'used_by'}" if r.relationship_type == "uses" else r.relationship_type
        grouped.setdefault(f"{label}:{other.obj_type}", []).append(
            {**attack_row(other), "how": (r.description or "")[:300]})
    for v in grouped.values():
        v.sort(key=lambda x: x["external_id"] or x["name"])

    if obj.obj_type == "technique":
        data["technique"] = technique_detail(session, obj)

    docs = session.scalars(
        select(Document).where(Document.id.in_(select(cast(EntityLink.subject_id, Integer))
                                               .where(EntityLink.subject_type == "document",
                                                      EntityLink.object_type == "attack",
                                                      EntityLink.object_id == obj.stix_id)))
        .order_by(Document.published_at.desc().nullslast()).limit(25)).all()
    cve_ids = list(session.scalars(cves_mentioned_with(session, obj.stix_id)))
    vulns = session.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))
                            .order_by(Vulnerability.relevance_score.desc()).limit(50)).all() if cve_ids else []
    data["relationships"] = grouped
    data["documents"] = [document_row(d) for d in docs]
    data["vulnerabilities"] = [vuln_row(v) for v in vulns]
    data["correlation_note"] = ("CVE associations come from co-mentions in focused reports "
                                "(same article, ≤5 CVEs), not from MITRE.")
    return data
