"""NVD CVE API 2.0 worker.

Phase A — incremental sync by lastModified window (cursor in source state).
Phase B — enrichment: CVEs referenced by KEV / articles / recent exploits
          that have no NVD data yet (or stale data), fetched one-by-one and
          cached in ``nvd_cache``.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.ingestion.http import HttpClient
from app.models import EntityLink, NvdCache, Vulnerability, utcnow
from app.services import correlation
from app.services.normalize import MalformedRecord, parse_nvd_cve, valid_cve_id
from app.services.sanitize import aware, parse_dt

log = logging.getLogger("asber.workers.nvd")

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HOST = "services.nvd.nist.gov"
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=119)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def configure_rate_limit(http: HttpClient, settings: Settings) -> dict:
    key = settings.secret(settings.nvd_api_key)
    # NVD: 5 req / 30 s without key, 50 req / 30 s with key (keep a safety margin)
    http.rate_limiter.set_interval(HOST, 0.8 if key else 6.5)
    return {"apiKey": key} if key else {}


def fetch_cve(session: Session, http: HttpClient, settings: Settings, cve_id: str,
              max_age_days: int | None = None) -> dict | None:
    """Return the raw NVD CVE object, using the local cache when fresh."""
    cve_id = valid_cve_id(cve_id)
    max_age = timedelta(days=max_age_days if max_age_days is not None else settings.nvd_cache_days)
    cached = session.get(NvdCache, cve_id)
    if cached and aware(cached.fetched_at) > utcnow() - max_age:
        return cached.payload if cached.found else None
    headers = configure_rate_limit(http, settings)
    resp = http.get(API, params={"cveId": cve_id}, headers=headers, max_bytes=10 * 1024 * 1024)
    items = (resp.json() or {}).get("vulnerabilities") or []
    payload = items[0].get("cve") if items and isinstance(items[0], dict) else None
    if cached is None:
        cached = NvdCache(cve_id=cve_id)
        session.add(cached)
    cached.fetched_at = utcnow()
    cached.found = payload is not None
    cached.payload = payload or {}
    return payload


class NvdWorker(BaseWorker):
    key = "nvd"

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        headers = configure_rate_limit(ctx.http, ctx.settings)
        self._incremental(ctx, stats, headers)
        ctx.checkpoint(stats)
        self._enrich(ctx, stats)

    # -- Phase A -------------------------------------------------------
    def _incremental(self, ctx: WorkerContext, stats: RunStats, headers: dict) -> None:
        now = ctx.now
        cursor = parse_dt(ctx.state.get("last_mod_cursor")) or now - timedelta(days=ctx.settings.nvd_initial_days)
        track_after = now - timedelta(days=ctx.settings.nvd_track_days)
        while cursor < now:
            window_end = min(now, cursor + MAX_WINDOW)
            start_index = 0
            while True:
                params = {"lastModStartDate": _fmt(cursor), "lastModEndDate": _fmt(window_end),
                          "resultsPerPage": PAGE_SIZE, "startIndex": start_index}
                resp = ctx.http.get(API, params=params, headers=headers, max_bytes=ctx.source.max_bytes)
                page = resp.json()
                if not isinstance(page, dict) or not isinstance(page.get("vulnerabilities"), list):
                    raise MalformedRecord("NVD page missing 'vulnerabilities'")
                for item in page["vulnerabilities"]:
                    stats.fetched += 1
                    self._apply(ctx, stats, item.get("cve") if isinstance(item, dict) else None, track_after)
                total = int(page.get("totalResults") or 0)
                start_index += int(page.get("resultsPerPage") or PAGE_SIZE)
                ctx.checkpoint(stats)
                if start_index >= total or not page["vulnerabilities"]:
                    break
            cursor = window_end
            ctx.state["last_mod_cursor"] = cursor.isoformat()
            ctx.checkpoint(stats)

    def _apply(self, ctx, stats, cve, track_after) -> None:
        try:
            parsed = parse_nvd_cve(cve)
        except MalformedRecord as exc:
            stats.malformed += 1
            log.warning("skipping malformed NVD item", extra={"source": self.key, "error": str(exc)})
            return
        # Only start tracking recently published CVEs; always update ones we already know.
        track_new = bool(parsed["published"] and parsed["published"] >= track_after)
        created, changed = correlation.apply_nvd(ctx.session, parsed, track_new=track_new)
        if created or changed:
            stats.touched_cves.add(parsed["cve_id"])
        stats.new += int(created)
        stats.updated += int(changed and not created)
        if created or changed or ctx.session.get(Vulnerability, parsed["cve_id"]):
            cache = ctx.session.get(NvdCache, parsed["cve_id"]) or NvdCache(cve_id=parsed["cve_id"])
            cache.payload, cache.found, cache.fetched_at = cve, True, utcnow()
            ctx.session.add(cache)

    # -- Phase B -------------------------------------------------------
    def enrichment_candidates(self, session: Session, settings: Settings, now: datetime) -> list[str]:
        limit = settings.nvd_enrich_per_run
        stale = now - timedelta(days=settings.nvd_cache_days)
        ids = list(session.scalars(
            select(Vulnerability.cve_id)
            .where(or_(Vulnerability.nvd_fetched_at.is_(None), Vulnerability.nvd_fetched_at < stale))
            .where(or_(Vulnerability.in_kev.is_(True), Vulnerability.relevance_score >= 40))
            .order_by(Vulnerability.relevance_score.desc())
            .limit(limit)
        ))
        if len(ids) < limit:
            known = select(Vulnerability.cve_id)
            recently_checked = select(NvdCache.cve_id).where(NvdCache.fetched_at >= stale)
            recent = now - timedelta(days=30)
            more = session.scalars(
                select(EntityLink.object_id).distinct()
                .where(EntityLink.object_type == "cve", EntityLink.object_id.not_in(known),
                       EntityLink.object_id.not_in(recently_checked), EntityLink.observed_at >= recent)
                .limit(limit - len(ids))
            )
            ids.extend(more)
        return ids

    def _enrich(self, ctx: WorkerContext, stats: RunStats) -> None:
        for cve_id in self.enrichment_candidates(ctx.session, ctx.settings, ctx.now):
            try:
                cve = fetch_cve(ctx.session, ctx.http, ctx.settings, cve_id)
                if cve is None:
                    vuln = ctx.session.get(Vulnerability, cve_id)
                    if vuln:
                        vuln.nvd_fetched_at = utcnow()  # avoid hammering for unpublished/reserved ids
                    continue
                parsed = parse_nvd_cve(cve)
            except MalformedRecord as exc:
                stats.malformed += 1
                log.warning("enrichment skipped", extra={"source": self.key, "cve": cve_id, "error": str(exc)})
                continue
            stats.fetched += 1
            created, changed = correlation.apply_nvd(ctx.session, parsed, track_new=True)
            stats.new += int(created)
            stats.updated += int(changed and not created)
            stats.touched_cves.add(parsed["cve_id"])
        stats.notes.append("enrichment complete")
