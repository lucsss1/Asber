"""Ingestion scheduler process: ``python -m app.scheduler``.

* one APScheduler interval job per enabled source (independent, never overlapping)
* a bootstrap pass on startup (MITRE first, so name dictionaries exist)
* a manual-trigger poller (``POST /api/sources/{key}/run``)
* a maintenance job that recomputes time-decaying relevance scores
"""
from __future__ import annotations

import logging
import signal
import threading
import time
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from app.config import get_settings
from app.db import create_schema, session_factory, session_scope
from app.ingestion.base import run_worker, sync_registry
from app.ingestion.coordination import pop_run_requests, source_lock
from app.ingestion.http import HttpClient
from app.logging_setup import setup_logging
from app.models import Source, Vulnerability
from app.services import correlation
from app.services.sanitize import aware
from app.workers import build_worker

log = logging.getLogger("asber.scheduler")

BOOTSTRAP_ORDER = ["mitre_attack", "cisa_kev", "unit42", "talos", "bleepingcomputer", "krebs", "therecord",
                   "exploitdb", "nvd", "github"]

_http: HttpClient | None = None


def http_client() -> HttpClient:
    global _http
    if _http is None:
        s = get_settings()
        _http = HttpClient(s.http_user_agent, timeout=s.http_timeout_seconds, max_retries=s.http_max_retries)
    return _http


def run_source(key: str) -> None:
    with source_lock(key) as acquired:
        if not acquired:
            log.info("skip: run already in progress", extra={"source": key})
            return
        try:
            worker = build_worker(key)
        except KeyError as exc:
            log.warning(str(exc), extra={"source": key})
            return
        run_worker(worker, session_factory(), http_client())


def maintenance() -> None:
    """Recompute scores (recency decays) for everything touched in the last 60 days."""
    started = time.monotonic()
    since = datetime.now(timezone.utc) - timedelta(days=60)
    with session_scope() as session:
        ids = session.scalars(select(Vulnerability.cve_id).where(
            (Vulnerability.last_activity_at >= since) | (Vulnerability.relevance_score >= 30))).all()
        n = correlation.recompute_many(session, ids)
    log.info("maintenance", extra={"status": "success", "recomputed": n,
                                   "duration_ms": int((time.monotonic() - started) * 1000)})


def enabled_sources() -> list[Source]:
    with session_scope() as session:
        return list(session.scalars(select(Source).where(Source.enabled.is_(True))))


def bootstrap(sources: list[Source]) -> None:
    now = datetime.now(timezone.utc)
    by_key = {s.key: s for s in sources}
    order = [k for k in BOOTSTRAP_ORDER if k in by_key] + [k for k in by_key if k not in BOOTSTRAP_ORDER]
    for key in order:
        src = by_key[key]
        last = aware(src.last_successful_fetch)
        if last and now - last < timedelta(seconds=src.interval_seconds):
            continue  # still fresh
        run_source(key)
    maintenance()


def poll_triggers() -> None:
    for key in pop_run_requests():
        log.info("manual run requested", extra={"source": key})
        threading.Thread(target=run_source, args=(key,), daemon=True, name=f"manual-{key}").start()


def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    create_schema()
    with session_scope() as session:
        sync_registry(session, settings)
    sources = enabled_sources()

    scheduler = BackgroundScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1,
                                                                  "misfire_grace_time": 600})
    now = datetime.now(timezone.utc)
    for src in sources:
        scheduler.add_job(run_source, "interval", seconds=src.interval_seconds, args=[src.key], id=src.key,
                          jitter=min(120, src.interval_seconds // 10),
                          next_run_time=now + timedelta(seconds=src.interval_seconds))
    scheduler.add_job(poll_triggers, "interval", seconds=15, id="triggers")
    scheduler.add_job(maintenance, "interval", hours=6, id="maintenance",
                      next_run_time=now + timedelta(hours=6))
    scheduler.start()
    log.info("scheduler started", extra={"sources": [s.key for s in sources]})

    if settings.run_on_startup:
        threading.Thread(target=bootstrap, args=(sources,), daemon=True, name="bootstrap").start()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    scheduler.shutdown(wait=False)
    log.info("scheduler stopped")


if __name__ == "__main__":
    main()
