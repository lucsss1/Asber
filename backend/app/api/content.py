"""Exploits, research, news and document endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, cast, or_, select
from sqlalchemy.orm import Session

from app.api.common import Page, like_term, paginate, window_start
from app.api.vulnerabilities import cves_mentioned_with, resolve_attack
from app.db import get_db
from app.models import Document, EntityLink, Exploit
from app.services.views import document_entities, document_row, exploit_row

router = APIRouter(prefix="/api", tags=["content"])


@router.get("/exploits")
def list_exploits(
    session: Session = Depends(get_db),
    page: Page = Depends(),
    window: str | None = None,
    kind: list[str] | None = Query(None),
    source: str | None = None,
    platform: str | None = None,
    cve: str | None = None,
    q: str | None = None,
    sort: str = "recent",
):
    stmt = select(Exploit)
    start = window_start(window)
    if start:
        stmt = stmt.where(or_(Exploit.published_at >= start, Exploit.collected_at >= start))
    if kind:
        stmt = stmt.where(Exploit.kind.in_(kind))
    if source:
        stmt = stmt.where(Exploit.source_key == source)
    if platform:
        stmt = stmt.where(Exploit.platform.ilike(like_term(platform)))
    if cve:
        # entity_links.subject_id is a string (it addresses several entity types)
        ids = select(cast(EntityLink.subject_id, Integer)).where(EntityLink.subject_type == "exploit",
                                                                 EntityLink.object_type == "cve",
                                                                 EntityLink.object_id == cve.upper())
        stmt = stmt.where(Exploit.id.in_(ids))
    if q:
        term = like_term(q)
        stmt = stmt.where(or_(Exploit.title.ilike(term), Exploit.description.ilike(term),
                              Exploit.external_id.ilike(term)))
    orders = {"recent": (Exploit.published_at.desc().nullslast(),),
              "collected": (Exploit.collected_at.desc(),),
              "stars": (Exploit.stars.desc().nullslast(),)}
    if sort not in orders:
        raise HTTPException(400, f"sort must be one of {sorted(orders)}")
    return paginate(session, stmt.order_by(*orders[sort]), page, exploit_row)


@router.get("/documents")
def list_documents(
    session: Session = Depends(get_db),
    page: Page = Depends(),
    doc_type: list[str] | None = Query(None),
    window: str | None = None,
    source: str | None = None,
    tier: list[int] | None = Query(None),
    cve: str | None = None,
    actor: str | None = None,
    exploitation: bool = False,
    q: str | None = None,
):
    stmt = select(Document)
    start = window_start(window)
    if start:
        stmt = stmt.where(Document.published_at >= start)
    if doc_type:
        stmt = stmt.where(Document.doc_type.in_(doc_type))
    if source:
        stmt = stmt.where(Document.source_key == source)
    if tier:
        stmt = stmt.where(Document.tier.in_(tier))
    if exploitation:
        stmt = stmt.where(Document.reports_exploitation.is_(True))
    if cve:
        ids = select(cast(EntityLink.subject_id, Integer)).where(EntityLink.subject_type == "document",
                                                                 EntityLink.object_type == "cve",
                                                                 EntityLink.object_id == cve.upper())
        stmt = stmt.where(Document.id.in_(ids))
    if actor:
        obj = resolve_attack(session, actor)
        if obj is not None:
            ids = select(cast(EntityLink.subject_id, Integer)).where(EntityLink.subject_type == "document",
                                                                     EntityLink.object_type == "attack",
                                                                     EntityLink.object_id == obj.stix_id)
            stmt = stmt.where(Document.id.in_(ids))
        else:
            stmt = stmt.where(Document.id.is_(None))
    if q:
        term = like_term(q)
        stmt = stmt.where(or_(Document.title.ilike(term), Document.summary.ilike(term)))

    result = paginate(session, stmt.order_by(Document.published_at.desc().nullslast()), page, lambda d: d)
    docs = result["items"]
    ents, cves = document_entities(session, [d.id for d in docs])
    result["items"] = [document_row(d, ents.get(d.id), cves.get(d.id)) for d in docs]
    return result


@router.get("/documents/by-actor/{stix_id}/cves")
def actor_cves(stix_id: str, session: Session = Depends(get_db)):
    return {"cve_ids": list(session.scalars(cves_mentioned_with(session, stix_id)))}
