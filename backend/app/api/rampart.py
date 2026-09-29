"""Rampart: the owner's environment.

Every handler here resolves its owner through ``deps.current_owner`` and does
all of its data access through ``services.rampart.repository``. Neither rule is
decorative: an inventory is a map of somebody's attack surface, and the only
way to be sure it is scoped correctly is for there to be one place where the
scoping happens.

Writes are reachable from the Next.js server only. The CORS policy in
``main.py`` allows GET and POST from the dashboard origin, so a browser cannot
issue the PATCH and DELETE below cross-origin at all; the frontend performs
them from Server Actions, server side.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.common import Page, paginate
from app.api.deps import current_owner
from app.api.vulnerabilities import build_query
from app.db import get_db
from app.models import Vulnerability
from app.services.rampart import matching, repository
from app.services.views import vuln_row

router = APIRouter(prefix="/api/rampart", tags=["rampart"])

CATEGORIES = {"firewall", "switch", "storage", "hypervisor", "os", "application", "other"}

#: Printable text without control characters. Asset labels are written by the
#: owner and rendered back to them; nothing here is ever sent to a source.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = _CONTROL.sub("", value).strip()
    return value or None


class AssetIn(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    category: str = Field(max_length=32)
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=300)
    version: str | None = Field(default=None, max_length=64)
    cpe: str | None = Field(default=None, max_length=400)
    catalogued: bool = False
    hardware_model: str | None = Field(default=None, max_length=120)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("label", "vendor", "product", "version", "cpe", "hardware_model", "notes")
    @classmethod
    def strip_control_characters(cls, v):
        return _clean(v)

    @field_validator("category")
    @classmethod
    def known_category(cls, v):
        v = (v or "").strip().lower()
        if v not in CATEGORIES:
            raise ValueError(f"category must be one of {sorted(CATEGORIES)}")
        return v


def _asset_row(asset) -> dict:
    return {
        "id": asset.id,
        "label": asset.label,
        "category": asset.category,
        "vendor": asset.vendor,
        "product": asset.product,
        "version": asset.version,
        "cpe": asset.cpe,
        "catalogued": asset.catalogued,
        "hardware_model": asset.hardware_model,
        "notes": asset.notes,
    }


def _match_row(match) -> dict:
    return {
        "cve_id": match.cve_id,
        "asset_id": match.asset_id,
        "state": match.state,
        "method": match.method,
        "confidence": match.confidence,
        "evidence": match.evidence,
        "exposure": match.exposure,
    }


@router.get("/environment")
def environment(session: Session = Depends(get_db), owner: str = Depends(current_owner)):
    env = repository.default_environment(session, owner)
    assets = repository.list_assets(session, owner, env.id)
    matches = repository.list_matches(session, owner, env.id)
    by_state: dict[str, int] = {}
    for m in matches:
        by_state[m.state] = by_state.get(m.state, 0) + 1
    session.commit()
    return {
        "id": env.id,
        "name": env.name,
        "assets": [_asset_row(a) for a in assets],
        "asset_limit": repository.MAX_ASSETS,
        "counts": {
            "affected": by_state.get(matching.AFFECTED, 0),
            "possibly_affected": by_state.get(matching.POSSIBLY_AFFECTED, 0),
            "not_affected": by_state.get(matching.NOT_AFFECTED, 0),
        },
    }


@router.get("/catalogue")
def catalogue(q: str = Query(min_length=2, max_length=80),
              session: Session = Depends(get_db),
              owner: str = Depends(current_owner)):
    """Vendor/product suggestions from data already collected.

    Reads nothing owned, so it carries no environment data — but it stays on
    this router so that the whole surface sits behind one access rule.
    """
    return {"items": repository.catalogue(session, q)}


@router.post("/assets", status_code=201)
def create_asset(payload: AssetIn, session: Session = Depends(get_db),
                 owner: str = Depends(current_owner)):
    if repository.count_assets(session, owner) >= repository.MAX_ASSETS:
        raise HTTPException(409, f"asset limit reached ({repository.MAX_ASSETS})")
    env = repository.default_environment(session, owner)
    asset = repository.create_asset(session, owner, env.id, **payload.model_dump())
    repository.recompute_asset(session, owner, asset.id)
    session.commit()
    return _asset_row(asset)


@router.patch("/assets/{asset_id}")
def update_asset(asset_id: int, payload: AssetIn, session: Session = Depends(get_db),
                 owner: str = Depends(current_owner)):
    asset = repository.update_asset(session, owner, asset_id, **payload.model_dump())
    if asset is None:
        raise HTTPException(404, "asset not found")
    repository.recompute_asset(session, owner, asset.id)
    session.commit()
    return _asset_row(asset)


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, session: Session = Depends(get_db),
                 owner: str = Depends(current_owner)):
    if not repository.delete_asset(session, owner, asset_id):
        raise HTTPException(404, "asset not found")
    session.commit()


@router.get("/threats")
def threats(
    session: Session = Depends(get_db),
    owner: str = Depends(current_owner),
    page: Page = Depends(),
    state: list[str] | None = Query(None),
    window: str | None = None,
    kev: bool = False,
    exploited: bool = False,
    exploit: bool = False,
    poc: bool = False,
    severity: list[str] | None = Query(None),
    tag: list[str] | None = Query(None),
    platform: list[str] | None = Query(None),
    technique: str | None = None,
    min_score: int | None = Query(None, ge=0, le=100),
    sort: str = "relevance",
):
    """The existing threat table, narrowed to what this environment runs.

    The filters are the ones the rest of the dashboard already uses — this
    reuses ``vulnerabilities.build_query`` rather than growing a second, subtly
    different query builder.
    """
    for s in state or []:
        if s not in (matching.AFFECTED, matching.POSSIBLY_AFFECTED, matching.NOT_AFFECTED):
            raise HTTPException(400, "state must be affected, possibly_affected or not_affected")

    env = repository.default_environment(session, owner)
    cve_ids = repository.matched_cve_ids(session, owner, env.id, state)
    session.commit()
    if not cve_ids:
        return {"total": 0, "page": page.page, "page_size": page.page_size, "items": [], "matches": {}}

    stmt = build_query(session, window=window, kev=kev, exploited=exploited, exploit=exploit, poc=poc,
                       severity=severity, tag=tag, platform=platform, technique=technique,
                       min_score=min_score, sort=sort)
    stmt = stmt.where(Vulnerability.cve_id.in_(cve_ids))
    result = paginate(session, stmt, page, vuln_row)

    # Every row carries its verdict and the sentence behind it, so the table
    # never shows a state the reader cannot interrogate.
    shown = {item["cve_id"] for item in result["items"]}
    result["matches"] = {
        m.cve_id: _match_row(m)
        for m in repository.list_matches(session, owner, env.id, state)
        if m.cve_id in shown
    }
    return result
