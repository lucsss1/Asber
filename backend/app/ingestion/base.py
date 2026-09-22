"""Worker framework.

Each source has an independent worker. ``run_worker`` wraps a worker's
``sync`` in bookkeeping so that:

* a failure in one source never affects the others,
* freshness fields on ``sources`` are always updated,
* every run is recorded in ``ingestion_runs``,
* a structured log line is emitted per run.
"""
from __future__ import annotations

import logging
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.ingestion.http import HttpClient
from app.ingestion.registry import REGISTRY_BY_KEY, SOURCE_REGISTRY, SourceDef
from app.models import IngestionRun, Source, utcnow
from app.services import correlation

log = logging.getLogger("asber.ingestion")


@dataclass
class RunStats:
    fetched: int = 0
    new: int = 0
    updated: int = 0
    skipped: int = 0
    malformed: int = 0
    not_modified: bool = False
    touched_cves: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)


@dataclass
class WorkerContext:
    session: Session
    http: HttpClient
    settings: Settings
    source: SourceDef
    state: dict
    now: datetime

    def checkpoint(self, stats: RunStats) -> None:
        """Commit progress so far (recomputing touched CVEs) and persist the cursor state.
        Used by long-running workers so a late failure doesn't discard earlier pages."""
        if stats.touched_cves:
            correlation.recompute_many(self.session, stats.touched_cves)
            stats.touched_cves.clear()
        source = self.session.get(Source, self.source.key)
        if source is not None:
            source.state = dict(self.state)
        self.session.commit()


class BaseWorker:
    key: str = ""

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:  # pragma: no cover - interface
        raise NotImplementedError


def sync_registry(session: Session, settings: Settings | None = None) -> None:
    """Insert/update the ``sources`` table from SOURCE_REGISTRY (keeps runtime state)."""
    settings = settings or get_settings()
    for sdef in SOURCE_REGISTRY:
        row = session.get(Source, sdef.key)
        enabled = sdef.enabled_by_default and sdef.worker is not None
        if sdef.key in settings.enabled_overrides:
            enabled = sdef.worker is not None
        if sdef.key in settings.disabled_overrides:
            enabled = False
        if sdef.requires_auth and sdef.auth_env and not settings.configured_credentials().get(sdef.auth_env):
            enabled = False
        values = dict(
            name=sdef.name, homepage=sdef.homepage, endpoint=sdef.endpoint, category=sdef.category,
            source_type=sdef.source_type, tier=sdef.tier, method=sdef.method, phase=sdef.phase,
            requires_auth=sdef.requires_auth, enabled=enabled,
            interval_seconds=settings.interval_override(sdef.key) or sdef.interval,
        )
        if row is None:
            session.add(Source(key=sdef.key, state={}, **values))
        else:
            for k, v in values.items():
                setattr(row, k, v)
    session.commit()


def run_worker(
    worker: BaseWorker,
    session_maker: sessionmaker,
    http: HttpClient,
    settings: Settings | None = None,
) -> IngestionRun:
    settings = settings or get_settings()
    sdef = REGISTRY_BY_KEY[worker.key]
    started = time.monotonic()
    stats = RunStats()
    status, error = "success", None

    with session_maker() as session:
        source = session.get(Source, worker.key)
        if source is None:
            sync_registry(session, settings)
            source = session.get(Source, worker.key)
        run = IngestionRun(source_key=worker.key, started_at=utcnow(), status="running")
        source.last_attempt = run.started_at
        session.add(run)
        session.commit()
        run_id = run.id
        state = dict(source.state or {})

    session = session_maker()
    try:
        ctx = WorkerContext(session=session, http=http, settings=settings, source=sdef, state=state, now=utcnow())
        worker.sync(ctx, stats)
        if stats.touched_cves:
            correlation.recompute_many(session, stats.touched_cves)
        session.commit()
        if stats.not_modified:
            status = "not_modified"
    except Exception as exc:  # noqa: BLE001 — isolate every source failure
        session.rollback()
        status, error = "error", f"{type(exc).__name__}: {exc}"
        log.error("worker failed", extra={"source": worker.key, "error": error,
                                          "trace": traceback.format_exc(limit=5)})
    finally:
        session.close()

    duration_ms = int((time.monotonic() - started) * 1000)
    with session_maker() as session:
        source = session.get(Source, worker.key)
        run = session.get(IngestionRun, run_id)
        now = utcnow()
        run.finished_at = now
        run.status = status
        run.items_fetched, run.items_new, run.items_updated = stats.fetched, stats.new, stats.updated
        run.duration_ms = duration_ms
        run.error = error
        source.last_status = status
        source.latency_ms = duration_ms
        source.items_fetched, source.items_new, source.items_updated = stats.fetched, stats.new, stats.updated
        if status == "error":
            source.last_error = error
            source.consecutive_failures = (source.consecutive_failures or 0) + 1
        else:
            source.last_error = None
            source.consecutive_failures = 0
            source.last_successful_fetch = now
            source.state = state  # cursors only persist after a successful run
        session.commit()
        session.refresh(run)

    log.info("ingestion run", extra={
        "source": worker.key, "status": status, "items_fetched": stats.fetched, "items_new": stats.new,
        "items_updated": stats.updated, "items_malformed": stats.malformed, "duration_ms": duration_ms,
        "error": error, "notes": stats.notes[:5],
    })
    return run
