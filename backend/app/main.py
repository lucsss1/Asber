"""FastAPI application (read-only API over the local threat-intelligence database)."""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api import attack, content, dashboard, vulnerabilities
from app.config import get_settings
from app.db import create_schema, session_scope
from app.ingestion.base import sync_registry
from app.logging_setup import setup_logging

log = logging.getLogger("asber.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings.log_level)
    create_schema()
    with session_scope() as session:
        sync_registry(session, settings)
    log.info("api started", extra={"version": __version__})
    yield


app = FastAPI(
    title="Asber API",
    version=__version__,
    description="Local threat-intelligence aggregation, correlation and prioritisation.",
    lifespan=lifespan,
)

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _settings.cors_origins.split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    """Simple per-client token bucket (defence in depth for a locally bound service)."""
    limit = get_settings().api_rate_limit_per_minute
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _hits[client]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= limit:
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429,
                            headers={"Retry-After": "30"})
    bucket.append(now)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(dashboard.router)
app.include_router(vulnerabilities.router)
app.include_router(content.router)
app.include_router(attack.router)


@app.get("/api/health")
def health():
    from sqlalchemy import select

    from app.models import Source

    with session_scope() as session:
        sources = len(session.scalars(select(Source.key)).all())
    return {"status": "ok", "version": __version__, "sources_registered": sources}
