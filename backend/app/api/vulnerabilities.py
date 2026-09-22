"""Vulnerability / threat endpoints (list, detail, export)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.common import Page, json_list_contains, like_term, paginate, window_start
from app.config import get_settings
from app.db import get_db
from app.models import AttackObject, EntityLink, SourceReference, Vulnerability
from app.services import correlation, export, views
from app.services.normalize import CVE_ID_RE
from app.services.views import cve_detail, vuln_row

log = logging.getLogger("asber.api")
router = APIRouter(prefix="/api", tags=["vulnerabilities"])

SORTS = {
    "relevance": (Vulnerability.relevance_score.desc(), Vulnerability.last_activity_at.desc()),
    "recent": (Vulnerability.last_activity_at.desc().nullslast(),),
    "published": (Vulnerability.published.desc().nullslast(),),
    "cvss": (Vulnerability.cvss_score.desc().nullslast(),),
    "kev": (Vulnerability.kev_date_added.desc().nullslast(),),
    "updated": (Vulnerability.updated_at.desc(),),
}


def cves_mentioned_with(session: Session, stix_id: str):
    """CVEs that appear in the same focused report as an ATT&CK entity."""
    doc_ids = select(EntityLink.subject_id).where(
        EntityLink.subject_type == "document", EntityLink.object_type == "attack",
        EntityLink.object_id == stix_id, EntityLink.relation == "mentions")
    return select(EntityLink.object_id).where(
        EntityLink.subject_type == "document", EntityLink.subject_id.in_(doc_ids),
        EntityLink.object_type == "cve", EntityLink.confidence == "high")


def resolve_attack(session: Session, value: str) -> AttackObject | None:
    return session.scalar(select(AttackObject).where(
        or_(AttackObject.stix_id == value, AttackObject.external_id == value.upper(),
            AttackObject.name == value)).limit(1))


def build_query(session: Session, *, window=None, kev=None, exploited=None, exploit=None, poc=None,
                severity=None, tag=None, platform=None, vendor=None, product=None, q=None, source=None,
                actor=None, technique=None, min_score=None, sort="relevance"):
    stmt = select(Vulnerability)
    start = window_start(window)
    if start:
        stmt = stmt.where(Vulnerability.last_activity_at >= start)
    if kev:
        stmt = stmt.where(Vulnerability.in_kev.is_(True))
    if exploited:
        stmt = stmt.where(Vulnerability.actively_exploited.is_(True))
    if exploit:
        stmt = stmt.where(Vulnerability.has_exploit.is_(True))
    if poc:
        stmt = stmt.where(Vulnerability.has_poc.is_(True))
    if severity:
        stmt = stmt.where(Vulnerability.cvss_severity.in_([s.upper() for s in severity]))
    for t in tag or []:
        stmt = stmt.where(json_list_contains(Vulnerability.tags, t))
    for p in platform or []:
        stmt = stmt.where(json_list_contains(Vulnerability.platforms, p))
    if vendor:
        stmt = stmt.where(Vulnerability.vendor.ilike(like_term(vendor)))
    if product:
        stmt = stmt.where(Vulnerability.product.ilike(like_term(product)))
    if min_score is not None:
        stmt = stmt.where(Vulnerability.relevance_score >= min_score)
    if q:
        term = like_term(q)
        stmt = stmt.where(or_(Vulnerability.cve_id.ilike(term), Vulnerability.title.ilike(term),
                              Vulnerability.description.ilike(term), Vulnerability.vendor.ilike(term),
                              Vulnerability.product.ilike(term)))
    if source:
        from_refs = select(SourceReference.cve_id).where(SourceReference.source_key == source)
        from_links = select(EntityLink.object_id).where(EntityLink.object_type == "cve",
                                                        EntityLink.source_key == source)
        stmt = stmt.where(or_(Vulnerability.cve_id.in_(from_refs), Vulnerability.cve_id.in_(from_links)))
    if actor:
        obj = resolve_attack(session, actor)
        if obj is None:
            raise HTTPException(404, f"unknown ATT&CK entity: {actor}")
        stmt = stmt.where(Vulnerability.cve_id.in_(cves_mentioned_with(session, obj.stix_id)))
    if technique:
        obj = resolve_attack(session, technique)
        conds = [json_list_contains(Vulnerability.techniques, technique.upper())]
        if obj is not None:
            conds.append(Vulnerability.cve_id.in_(cves_mentioned_with(session, obj.stix_id)))
        stmt = stmt.where(or_(*conds))
    return stmt.order_by(*SORTS.get(sort, SORTS["relevance"]))


@router.get("/vulnerabilities")
def list_vulnerabilities(
    session: Session = Depends(get_db),
    page: Page = Depends(),
    window: str | None = None,
    kev: bool = False,
    exploited: bool = False,
    exploit: bool = False,
    poc: bool = False,
    severity: list[str] | None = Query(None),
    tag: list[str] | None = Query(None),
    platform: list[str] | None = Query(None),
    vendor: str | None = None,
    product: str | None = None,
    q: str | None = None,
    source: str | None = None,
    actor: str | None = None,
    technique: str | None = None,
    min_score: int | None = Query(None, ge=0, le=100),
    sort: str = "relevance",
):
    stmt = build_query(session, window=window, kev=kev, exploited=exploited, exploit=exploit, poc=poc,
                       severity=severity, tag=tag, platform=platform, vendor=vendor, product=product, q=q,
                       source=source, actor=actor, technique=technique, min_score=min_score, sort=sort)
    return paginate(session, stmt, page, vuln_row)


def _on_demand_lookup(session: Session, cve_id: str) -> bool:
    """Fetch an unknown CVE from NVD on demand (cached). Returns True if it is now known."""
    from app.ingestion.http import FetchError
    from app.workers.nvd import fetch_cve

    settings = get_settings()
    http = _api_http()
    try:
        payload = fetch_cve(session, http, settings, cve_id)
    except (FetchError, ValueError) as exc:
        log.warning("on-demand NVD lookup failed", extra={"cve": cve_id, "error": str(exc)})
        return False
    if not payload:
        session.commit()
        return False
    from app.services.normalize import parse_nvd_cve

    correlation.apply_nvd(session, parse_nvd_cve(payload), track_new=True)
    correlation.recompute_vulnerability(session, cve_id)
    session.commit()
    return True


_http_client = None


def _api_http():
    """Small, low-retry client for on-demand lookups from the API process."""
    global _http_client
    if _http_client is None:
        from app.ingestion.http import HttpClient

        s = get_settings()
        _http_client = HttpClient(s.http_user_agent, timeout=15.0, max_retries=1)
    return _http_client


@router.get("/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str, session: Session = Depends(get_db)):
    cve_id = cve_id.strip().upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(400, "invalid CVE id")
    detail = cve_detail(session, cve_id)
    if detail is None:
        if not _on_demand_lookup(session, cve_id):
            raise HTTPException(404, f"{cve_id} is not tracked and was not found in the NVD")
        detail = cve_detail(session, cve_id)
    return detail


@router.get("/vulnerabilities/{cve_id}/export")
def export_vulnerability(cve_id: str, format: str = "markdown", session: Session = Depends(get_db)):
    detail = get_vulnerability(cve_id, session)
    cve_id = detail["cve_id"]
    if format == "json":
        return Response(export.to_json(detail), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{cve_id}.json"'})
    if format == "csv":
        return Response(export.to_csv(detail), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{cve_id}.csv"'})
    if format in ("md", "markdown"):
        return Response(export.to_markdown(detail), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{cve_id}.md"'})
    raise HTTPException(400, "format must be json, csv or markdown")


@router.get("/filters/options")
def filter_options(session: Session = Depends(get_db)):
    from app.ingestion.registry import SOURCE_REGISTRY

    vendors = session.scalars(
        select(Vulnerability.vendor).where(Vulnerability.vendor.is_not(None),
                                           Vulnerability.relevance_score >= 20)
        .distinct().order_by(Vulnerability.vendor).limit(300)).all()
    return {
        "windows": ["24h", "7d", "30d", "90d", "all"],
        "sorts": list(SORTS),
        "tags": ["rce", "privilege_escalation", "auth_bypass", "sqli", "path_traversal", "memory_corruption",
                 "info_disclosure", "dos"],
        "platforms": ["windows", "linux", "macos", "android", "cloud", "active_directory", "identity", "web",
                      "network"],
        "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "vendors": vendors,
        "sources": [{"key": s.key, "name": s.name, "tier": s.tier} for s in SOURCE_REGISTRY],
        "tiers": views.TIER_LABELS,
    }
