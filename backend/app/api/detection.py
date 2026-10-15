"""Detection rules — what the public corpus can catch.

The page this serves answers one question: of the things Asber tracks, which
ones does somebody already know how to detect? That is why the CVE filter
matters more than the volume. Measured on the current corpus, 3,302 rules
produce 212 rule-to-CVE edges covering 96 CVEs, and every one of those 96 is in
CISA KEV and flagged as actively exploited. The sparse half of the data lands
entirely on the half of the corpus that matters.

Nothing here executes a rule. The detection body is returned as the text it was
stored as, because a reader who cannot see what a rule looks for has no way to
judge whether "covered" means anything.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.common import Page, like_term, paginate
from app.db import get_db
from app.models import AttackObject, DetectionRule, EntityLink, Vulnerability

router = APIRouter(prefix="/api/detection", tags=["detection"])

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
SORTS = {
    "level": (func.coalesce(DetectionRule.level, "").desc(), DetectionRule.title),
    "title": (DetectionRule.title,),
    "recent": (DetectionRule.collected_at.desc(), DetectionRule.title),
}


def rule_row(rule: DetectionRule) -> dict:
    return {
        "id": rule.id,
        "external_id": rule.external_id,
        "title": rule.title,
        "description": rule.description,
        "url": rule.url,
        "format": rule.rule_format,
        "status": rule.status,
        "level": rule.level,
        "logsource": rule.logsource or {},
        "techniques": rule.techniques or [],
        "cve_ids": rule.cve_ids or [],
        "falsepositives": rule.falsepositives or [],
        "references": rule.references or [],
        "author": rule.author,
        "release": rule.release,
        "source_key": rule.source_key,
    }


@router.get("/rules")
def rules(
    session: Session = Depends(get_db),
    page: Page = Depends(),
    q: str | None = None,
    level: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    technique: str | None = None,
    cve: str | None = None,
    #: only rules that name a CVE this deployment actually tracks
    has_cve: bool = False,
    sort: str = "level",
):
    for value, allowed, name in ((level, LEVELS, "level"), (status, STATUSES, "status")):
        for v in value or []:
            if v not in allowed:
                raise HTTPException(400, f"{name} must be one of {sorted(allowed)}")
    if sort not in SORTS:
        # Falling back silently would answer 200 for a request never honoured.
        raise HTTPException(400, f"sort must be one of {sorted(SORTS)}")

    stmt = select(DetectionRule)
    if level:
        stmt = stmt.where(DetectionRule.level.in_(level))
    if status:
        stmt = stmt.where(DetectionRule.status.in_(status))
    if q:
        term = like_term(q)
        stmt = stmt.where(or_(DetectionRule.title.ilike(term), DetectionRule.description.ilike(term)))
    if technique:
        stmt = stmt.where(DetectionRule.id.in_(_rule_ids_for_technique(session, technique)))
    if cve:
        stmt = stmt.where(DetectionRule.id.in_(_rule_ids_for_cve(session, cve.upper())))
    if has_cve:
        stmt = stmt.where(DetectionRule.id.in_(select(_cve_edge().c.rule_id)))

    return paginate(session, stmt.order_by(*SORTS[sort]), page, rule_row)


def _cve_edge():
    """Rule ids that point at a CVE this deployment actually has a row for.

    The join against ``vulnerabilities`` is the point: a rule tagged with a CVE
    nobody here tracks says nothing about this corpus.
    """
    return (
        select(func.cast(EntityLink.subject_id, DetectionRule.id.type).label("rule_id"),
               EntityLink.object_id.label("cve_id"))
        .join(Vulnerability, Vulnerability.cve_id == EntityLink.object_id)
        .where(EntityLink.subject_type == "rule", EntityLink.object_type == "cve")
        .subquery()
    )


def _rule_ids_for_cve(session: Session, cve_id: str):
    return select(func.cast(EntityLink.subject_id, DetectionRule.id.type)).where(
        EntityLink.subject_type == "rule", EntityLink.object_type == "cve",
        EntityLink.object_id == cve_id)


def resolve_technique_stix(session: Session, technique: str) -> str:
    """A technique id (T1190) to its STIX id; a STIX id passes through.

    ``obj_type`` is not optional here. ATT&CK carries the same ``external_id``
    on more than one object -- T1190 is both the technique and the
    course-of-action that mitigates it -- and without the constraint this
    resolved to ``course-of-action--65da1eb6``, which no rule points at. The
    endpoint then answered 200 with an empty list: the failure mode that looks
    like "no data" rather than like a bug.

    Returns the input unchanged when nothing resolves, so an unknown technique
    matches no rules instead of matching everything.
    """
    if technique.startswith("attack-pattern--"):
        return technique
    return session.scalar(select(AttackObject.stix_id).where(
        func.upper(AttackObject.external_id) == technique.upper(),
        AttackObject.obj_type == "technique")) or technique


def _rule_ids_for_technique(session: Session, technique: str):
    return select(func.cast(EntityLink.subject_id, DetectionRule.id.type)).where(
        EntityLink.subject_type == "rule", EntityLink.object_type == "attack",
        EntityLink.object_id == resolve_technique_stix(session, technique))


@router.get("/rules/{rule_id}")
def rule_detail(rule_id: int, session: Session = Depends(get_db)):
    rule = session.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(404, "rule not found")
    row = rule_row(rule)
    # The body is what makes the verdict interrogable, so it only ships on the
    # detail route rather than bloating every row of a listing.
    row["detection"] = rule.detection
    row["tags"] = rule.tags or []
    techniques = session.scalars(
        select(AttackObject).where(AttackObject.stix_id.in_(
            select(EntityLink.object_id).where(
                EntityLink.subject_type == "rule", EntityLink.subject_id == str(rule.id),
                EntityLink.object_type == "attack")))).all()
    row["attack"] = [{"stix_id": a.stix_id, "external_id": a.external_id, "name": a.name} for a in techniques]
    return row


@router.get("/overview")
def overview(session: Session = Depends(get_db)):
    """What the corpus is covered by, in the numbers the page leads with."""
    edge = _cve_edge()
    total = session.scalar(select(func.count()).select_from(DetectionRule)) or 0
    by_level = dict(session.execute(
        select(DetectionRule.level, func.count()).group_by(DetectionRule.level)).all())
    techniques = session.scalar(select(func.count(func.distinct(EntityLink.object_id))).where(
        EntityLink.subject_type == "rule", EntityLink.object_type == "attack")) or 0
    covered = session.scalar(select(func.count(func.distinct(edge.c.cve_id)))) or 0
    covered_kev = session.scalar(
        select(func.count(func.distinct(Vulnerability.cve_id)))
        .select_from(Vulnerability).join(edge, edge.c.cve_id == Vulnerability.cve_id)
        .where(Vulnerability.in_kev.is_(True))) or 0
    kev_total = session.scalar(select(func.count()).select_from(Vulnerability)
                               .where(Vulnerability.in_kev.is_(True))) or 0
    releases = session.scalars(select(DetectionRule.release).distinct()).all()
    return {
        "rules": total,
        "by_level": {k: v for k, v in by_level.items() if k},
        "techniques_covered": techniques,
        "cves_covered": covered,
        "kev_covered": covered_kev,
        "kev_total": kev_total,
        "releases": sorted(r for r in releases if r),
    }
