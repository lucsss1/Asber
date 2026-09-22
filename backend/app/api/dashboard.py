"""Dashboard overview, global search, source health, settings and metrics."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.common import like_term, window_start
from app.config import get_settings
from app.db import get_db
from app.ingestion.coordination import request_run
from app.ingestion.registry import REGISTRY_BY_KEY, SOURCE_REGISTRY
from app.models import (
    AttackObject,
    Document,
    EntityLink,
    Exploit,
    IngestionRun,
    Source,
    Vulnerability,
)
from app.services.normalize import CVE_ID_RE
from app.services.sanitize import aware
from app.services.scoring import WEIGHTS
from app.services.views import attack_row, document_row, exploit_row, iso, source_info, vuln_row

router = APIRouter(prefix="/api", tags=["dashboard"])


def _count(session: Session, stmt) -> int:
    return session.scalar(select(func.count()).select_from(stmt.subquery())) or 0


@router.get("/dashboard/overview")
def overview(session: Session = Depends(get_db), window: str = "24h"):
    start = window_start(window) or datetime(1970, 1, 1, tzinfo=timezone.utc)
    start_date = start.date()

    new_actors = (select(AttackObject.stix_id).join(
        EntityLink, EntityLink.object_id == AttackObject.stix_id)
        .where(EntityLink.object_type == "attack", EntityLink.observed_at >= start).distinct())

    cards = {
        "actively_exploited": _count(session, select(Vulnerability.cve_id).where(
            Vulnerability.actively_exploited.is_(True), Vulnerability.last_activity_at >= start)),
        "kev_added": _count(session, select(Vulnerability.cve_id).where(Vulnerability.kev_date_added >= start_date)),
        "new_cves": _count(session, select(Vulnerability.cve_id).where(Vulnerability.published >= start)),
        # Published date, not collection date: the first Exploit-DB import would
        # otherwise report its whole 46k-row backlog as "new this week".
        "new_exploits": _count(session, select(Exploit.id).where(
            Exploit.kind == "exploit", Exploit.published_at >= start)),
        "new_pocs": _count(session, select(Exploit.id).where(Exploit.kind == "poc", Exploit.collected_at >= start)),
        "threat_actors_seen": _count(session, new_actors.where(AttackObject.obj_type == "group")),
        "malware_seen": _count(session, new_actors.where(AttackObject.obj_type.in_(("malware", "tool")))),
        "campaigns_seen": _count(session, new_actors.where(AttackObject.obj_type == "campaign")),
        "new_research": _count(session, select(Document.id).where(
            Document.doc_type.in_(("research", "advisory")), Document.published_at >= start)),
        "new_news": _count(session, select(Document.id).where(
            Document.doc_type == "news", Document.published_at >= start)),
        "new_detection_rules": _count(session, select(Exploit.id).where(
            Exploit.kind == "detection", Exploit.collected_at >= start)),
    }

    top = session.scalars(select(Vulnerability).where(Vulnerability.last_activity_at >= start)
                          .order_by(Vulnerability.relevance_score.desc(),
                                    Vulnerability.last_activity_at.desc()).limit(10)).all()
    research = session.scalars(select(Document).where(Document.doc_type.in_(("research", "advisory")))
                               .order_by(Document.published_at.desc().nullslast()).limit(8)).all()
    news = session.scalars(select(Document).where(Document.doc_type == "news")
                           .order_by(Document.published_at.desc().nullslast()).limit(8)).all()
    exploits = session.scalars(select(Exploit).order_by(Exploit.collected_at.desc()).limit(8)).all()

    trending_rows = session.execute(
        select(EntityLink.object_id, func.count(func.distinct(EntityLink.subject_id)).label("n"))
        .where(EntityLink.object_type == "attack", EntityLink.observed_at >= start,
               EntityLink.relation == "mentions")
        .group_by(EntityLink.object_id).order_by(func.count(func.distinct(EntityLink.subject_id)).desc())
        .limit(12)).all()
    objs = {a.stix_id: a for a in session.scalars(select(AttackObject).where(
        AttackObject.stix_id.in_([r[0] for r in trending_rows])))} if trending_rows else {}
    trending = [attack_row(objs[sid], n) for sid, n in trending_rows if sid in objs]

    sources = session.scalars(select(Source)).all()
    now = datetime.now(timezone.utc)
    stale = [s.key for s in sources if s.enabled and (
        s.last_successful_fetch is None or now - aware(s.last_successful_fetch) > timedelta(
            seconds=s.interval_seconds * 4))]
    return {
        "window": window,
        "generated_at": iso(now),
        "cards": cards,
        "top_threats": [vuln_row(v) for v in top],
        "latest_research": [document_row(d) for d in research],
        "latest_news": [document_row(d) for d in news],
        "latest_exploits": [exploit_row(e) for e in exploits],
        "trending_attack": trending,
        "source_health": {
            "total": len(sources),
            "enabled": sum(1 for s in sources if s.enabled),
            "errors": [s.key for s in sources if s.last_status == "error"],
            "stale": stale,
        },
        "phase_2_pending": [s.key for s in SOURCE_REGISTRY if s.phase >= 2],
    }


@router.get("/search")
def search(q: str = Query(min_length=2, max_length=200), session: Session = Depends(get_db), limit: int = 10):
    term = like_term(q)
    exact_cve = CVE_ID_RE.match(q.strip().upper())

    vulns = session.scalars(
        select(Vulnerability).where(or_(Vulnerability.cve_id.ilike(term), Vulnerability.title.ilike(term),
                                        Vulnerability.description.ilike(term), Vulnerability.vendor.ilike(term),
                                        Vulnerability.product.ilike(term)))
        .order_by(Vulnerability.relevance_score.desc()).limit(limit)).all()

    doc_stmt = select(Document)
    if session.bind.dialect.name == "postgresql":
        tsv = func.to_tsvector("english", func.coalesce(Document.title, "") + " "
                               + func.coalesce(Document.summary, ""))
        query = func.websearch_to_tsquery("english", q)
        doc_stmt = doc_stmt.where(tsv.op("@@")(query)).order_by(func.ts_rank(tsv, query).desc())
    else:
        doc_stmt = doc_stmt.where(or_(Document.title.ilike(term), Document.summary.ilike(term))) \
            .order_by(Document.published_at.desc().nullslast())
    docs = session.scalars(doc_stmt.limit(limit)).all()

    exploits = session.scalars(select(Exploit).where(
        or_(Exploit.title.ilike(term), Exploit.description.ilike(term), Exploit.external_id.ilike(term)))
        .order_by(Exploit.published_at.desc().nullslast()).limit(limit)).all()
    attack = session.scalars(select(AttackObject).where(
        AttackObject.revoked.is_(False), AttackObject.deprecated.is_(False),
        or_(AttackObject.name.ilike(term), AttackObject.external_id.ilike(term),
            cast(AttackObject.aliases, String).ilike(term))).limit(limit)).all()

    return {
        "query": q,
        "exact_cve": q.strip().upper() if exact_cve else None,
        "vulnerabilities": [vuln_row(v) for v in vulns],
        "documents": [document_row(d) for d in docs],
        "exploits": [exploit_row(e) for e in exploits],
        "attack": [attack_row(a) for a in attack],
    }


@router.get("/sources")
def list_sources(session: Session = Depends(get_db)):
    rows = session.scalars(select(Source).order_by(Source.category, Source.key)).all()
    now = datetime.now(timezone.utc)
    out = []
    for s in rows:
        sdef = REGISTRY_BY_KEY.get(s.key)
        last = aware(s.last_successful_fetch)
        age = (now - last).total_seconds() if last else None
        if not s.enabled:
            health = "disabled"
        elif s.last_status == "error":
            health = "error"
        elif age is None:
            health = "never_run"
        elif age > s.interval_seconds * 4:
            health = "stale"
        else:
            health = "ok"
        out.append({
            "key": s.key, "name": s.name, "homepage": s.homepage, "endpoint": s.endpoint,
            "category": s.category, "source_type": s.source_type, "tier": s.tier, "method": s.method,
            "phase": s.phase, "enabled": s.enabled, "requires_auth": s.requires_auth,
            "interval_seconds": s.interval_seconds, "health": health,
            "last_attempt": iso(s.last_attempt), "last_successful_fetch": iso(s.last_successful_fetch),
            "last_status": s.last_status, "last_error": s.last_error, "latency_ms": s.latency_ms,
            "items_fetched": s.items_fetched, "items_new": s.items_new, "items_updated": s.items_updated,
            "consecutive_failures": s.consecutive_failures,
            "implemented": bool(sdef and sdef.worker),
            "notes": sdef.notes if sdef else "", "rate_limit": sdef.rate_limit if sdef else "",
            "fields": list(sdef.fields) if sdef else [],
        })
    return {"sources": out}


@router.get("/sources/{key}/runs")
def source_runs(key: str, session: Session = Depends(get_db), limit: int = 25):
    if key not in REGISTRY_BY_KEY:
        raise HTTPException(404, "unknown source")
    runs = session.scalars(select(IngestionRun).where(IngestionRun.source_key == key)
                           .order_by(IngestionRun.started_at.desc()).limit(min(limit, 100))).all()
    return {"runs": [{"id": r.id, "status": r.status, "started_at": iso(r.started_at),
                      "finished_at": iso(r.finished_at), "items_fetched": r.items_fetched,
                      "items_new": r.items_new, "items_updated": r.items_updated,
                      "duration_ms": r.duration_ms, "error": r.error} for r in runs]}


@router.post("/sources/{key}/run")
def trigger_source(key: str, session: Session = Depends(get_db)):
    sdef = REGISTRY_BY_KEY.get(key)
    if sdef is None:
        raise HTTPException(404, "unknown source")
    if not sdef.worker:
        raise HTTPException(400, f"source {key} has no worker yet (phase {sdef.phase})")
    source = session.get(Source, key)
    if source is not None and not source.enabled:
        raise HTTPException(400, f"source {key} is disabled")
    queued = request_run(key)
    return {"queued": True, "delivered_to_scheduler": queued,
            "note": None if queued else "Redis is not configured; the scheduler picks up triggers only "
                                        "in single-process mode."}


@router.get("/settings")
def settings_view(session: Session = Depends(get_db)):
    s = get_settings()
    return {
        "credentials_configured": s.configured_credentials(),  # booleans only, never values
        "intervals": {row.key: row.interval_seconds for row in session.scalars(select(Source))},
        "scoring_weights": WEIGHTS,
        "features": {
            "malware_download_enabled": s.malware_download_enabled,
            "ai_provider": s.ai_provider,
            "redis_configured": bool(s.redis_url),
            "nvd_initial_days": s.nvd_initial_days,
            "github_max_cves_per_run": s.github_max_cves_per_run,
        },
        "safety": ["PoCs and exploits are never executed", "Malware samples are never downloaded",
                   "External HTML is stripped at ingestion", "API keys are never exposed to the frontend"],
    }


@router.get("/metrics")
def metrics(session: Session = Depends(get_db)):
    counts = {
        "vulnerabilities": _count(session, select(Vulnerability.cve_id)),
        "kev": _count(session, select(Vulnerability.cve_id).where(Vulnerability.in_kev.is_(True))),
        "exploits": _count(session, select(Exploit.id)),
        "documents": _count(session, select(Document.id)),
        "attack_objects": _count(session, select(AttackObject.stix_id)),
        "entity_links": _count(session, select(EntityLink.id)),
    }
    last_runs = session.execute(
        select(IngestionRun.source_key, func.max(IngestionRun.started_at)).group_by(IngestionRun.source_key)).all()
    return {"counts": counts, "last_runs": {k: iso(v) for k, v in last_runs}}
