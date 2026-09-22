"""Run selected source workers once, against the configured database.

Useful for a first fill or for verifying a source without waiting for the
scheduler:

    python -m scripts.collect_once cisa_kev unit42
    python -m scripts.collect_once --all
"""
from __future__ import annotations

import sys

from app.config import get_settings
from app.db import create_schema, session_factory, session_scope
from app.ingestion.base import run_worker, sync_registry
from app.ingestion.http import HttpClient
from app.logging_setup import setup_logging
from app.workers import build_worker, implemented_keys


def main(argv: list[str]) -> int:
    settings = get_settings()
    setup_logging(settings.log_level)
    create_schema()
    with session_scope() as session:
        sync_registry(session, settings)

    keys = [a for a in argv if not a.startswith("-")]
    if "--all" in argv or not keys:
        keys = implemented_keys()
    unknown = [k for k in keys if k not in implemented_keys()]
    if unknown:
        print(f"unknown or unimplemented source(s): {unknown}", file=sys.stderr)
        print(f"available: {implemented_keys()}", file=sys.stderr)
        return 2

    http = HttpClient(settings.http_user_agent, timeout=settings.http_timeout_seconds,
                      max_retries=settings.http_max_retries)
    failures = 0
    try:
        for key in keys:
            run = run_worker(build_worker(key), session_factory(), http, settings)
            print(f"{key:18} {run.status:13} fetched={run.items_fetched:6} new={run.items_new:5} "
                  f"updated={run.items_updated:5} {run.duration_ms:6}ms {run.error or ''}")
            failures += run.status == "error"
    finally:
        http.close()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
