"""Indicators — a lookup, not a feed.

The page this serves answers "I have this hash, URL or host from an alert; is
it known?". That is the only question these two sources can answer offline for
a reader with no SIEM to block in and no logs to cross against, and a list of
thirty thousand URLs answers nothing.

So the primary route is ``/lookup``. The listing exists underneath it for
context — what has been arriving — and is deliberately secondary.

Nothing here fetches a sample or submits anything to a scanner. The values are
returned as stored, and the URL rows are never requested.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Text, func, or_, select
from sqlalchemy.orm import Session

from app.api.common import Page, paginate
from app.db import get_db
from app.models import AttackObject, Indicator, utcnow
from app.services import indicators as ioc

router = APIRouter(prefix="/api/iocs", tags=["iocs"])

KINDS = (ioc.SHA256, ioc.MD5, ioc.SHA1, ioc.URL, ioc.DOMAIN, ioc.IPV4)


def indicator_row(row: Indicator) -> dict:
    return {
        "id": row.id,
        "kind": row.kind,
        "value": row.value,
        "host": row.host,
        "family": row.family,
        "attack_stix_id": row.attack_stix_id,
        "threat": row.threat,
        "status": row.status,
        "file_type": row.file_type,
        "mime_type": row.mime_type,
        "related": row.related or {},
        "tags": row.tags or [],
        "reporter": row.reporter,
        "reference_url": row.reference_url,
        "source_key": row.source_key,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


def _attack_for(session: Session, stix_ids: list[str]) -> dict:
    if not stix_ids:
        return {}
    rows = session.scalars(select(AttackObject).where(AttackObject.stix_id.in_(stix_ids))).all()
    return {a.stix_id: {"stix_id": a.stix_id, "external_id": a.external_id,
                        "name": a.name, "obj_type": a.obj_type} for a in rows}


@router.get("/lookup")
def lookup(q: str = Query(min_length=3, max_length=600), session: Session = Depends(get_db)):
    """Is this observable known, and what is known about it.

    A miss is an answer, and it is reported as one: ``found: false`` with the
    kind that was recognised, so the reader can tell "we have nothing on this"
    apart from "that is not something we index". The corpus is the recent
    window of two public feeds, never the whole internet, and the response
    says so rather than letting absence read as safety.
    """
    raw = (q or "").strip()
    kind = ioc.classify(raw)
    if kind is None:
        raise HTTPException(400, "not a hash, URL, domain or IPv4 address")

    value = ioc.normalise(raw)
    host = ioc.host_of(raw)
    conditions = [Indicator.value_norm == value]
    # A hash may be the sha256 of a row, or the md5/sha1 recorded beside it.
    if kind in (ioc.MD5, ioc.SHA1):
        # The md5 and sha1 of a sample live in ``related`` beside its sha256, so
        # one lookup answers for all three rather than only for the key hash.
        conditions.append(func.lower(func.cast(Indicator.related, Text)).contains(value))
    # A host finds every URL served from it, which is usually what is wanted.
    if host:
        conditions.append(Indicator.host == host)

    rows = session.scalars(
        select(Indicator).where(or_(*conditions))
        .order_by(Indicator.first_seen_at.desc().nullslast()).limit(50)).all()

    attack = _attack_for(session, [r.attack_stix_id for r in rows if r.attack_stix_id])
    return {
        "query": raw,
        "kind": kind,
        "found": bool(rows),
        "total": len(rows),
        "items": [indicator_row(r) for r in rows],
        "attack": attack,
        # Said out loud, because absence here is not evidence of safety.
        "scope": "the recent windows of MalwareBazaar and URLhaus",
    }


@router.get("/indicators")
def indicators(
    session: Session = Depends(get_db),
    page: Page = Depends(),
    kind: list[str] | None = Query(None),
    source: str | None = None,
    family: str | None = None,
    status: str | None = None,
    has_family: bool = False,
    window: str | None = None,
):
    """What has been arriving. Context for the lookup, not the product."""
    for k in kind or []:
        if k not in KINDS:
            raise HTTPException(400, f"kind must be one of {sorted(KINDS)}")

    stmt = select(Indicator)
    if kind:
        stmt = stmt.where(Indicator.kind.in_(kind))
    if source:
        stmt = stmt.where(Indicator.source_key == source)
    if family:
        stmt = stmt.where(Indicator.family.ilike(family))
    if status:
        stmt = stmt.where(Indicator.status == status)
    if has_family:
        stmt = stmt.where(Indicator.attack_stix_id.is_not(None))
    if window:
        days = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}.get(window)
        if days is None:
            raise HTTPException(400, "window must be 24h, 7d, 30d or 90d")
        stmt = stmt.where(Indicator.first_seen_at >= utcnow() - timedelta(days=days))

    return paginate(session, stmt.order_by(Indicator.first_seen_at.desc().nullslast()),
                    page, indicator_row)


@router.get("/overview")
def overview(session: Session = Depends(get_db)):
    """The numbers the page leads with, including the honest denominator."""
    by_kind = dict(session.execute(
        select(Indicator.kind, func.count()).group_by(Indicator.kind)).all())
    by_source = dict(session.execute(
        select(Indicator.source_key, func.count()).group_by(Indicator.source_key)).all())
    total = sum(by_kind.values())
    resolved = session.scalar(select(func.count()).select_from(Indicator)
                              .where(Indicator.attack_stix_id.is_not(None))) or 0
    families = session.scalar(select(func.count(func.distinct(Indicator.attack_stix_id)))
                              .where(Indicator.attack_stix_id.is_not(None))) or 0
    online = session.scalar(select(func.count()).select_from(Indicator)
                            .where(Indicator.status == "online")) or 0
    newest = session.scalar(select(func.max(Indicator.first_seen_at)))
    return {
        "total": total,
        "by_kind": by_kind,
        "by_source": by_source,
        "attack_resolved": resolved,
        "attack_families": families,
        "online": online,
        "newest": newest.isoformat() if newest else None,
    }
