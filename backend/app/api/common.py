from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Query
from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
           "90d": timedelta(days=90), "1y": timedelta(days=365)}


def window_start(window: str | None) -> datetime | None:
    if not window or window == "all":
        return None
    if window not in WINDOWS:
        raise HTTPException(400, f"window must be one of {sorted(WINDOWS)} or 'all'")
    return datetime.now(timezone.utc) - WINDOWS[window]


class Page:
    def __init__(self, page: int = Query(1, ge=1, le=10_000), page_size: int = Query(25, ge=1, le=100)):
        self.page = page
        self.page_size = page_size

    def apply(self, stmt):
        return stmt.limit(self.page_size).offset((self.page - 1) * self.page_size)


def paginate(session: Session, stmt, page: Page, serializer) -> dict:
    total = session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    items = session.scalars(page.apply(stmt)).all()
    return {"total": total, "page": page.page, "page_size": page.page_size,
            "items": [serializer(i) for i in items]}


def json_list_contains(column, value: str):
    """Portable "JSON list contains string" (JSONB in Postgres, JSON text in SQLite)."""
    safe = value.replace("%", "").replace("_", "\\_").replace('"', "")
    return cast(column, String).like(f'%"{safe}"%', escape="\\")


def like_term(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:200] + "%"
