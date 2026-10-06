"""Every query that touches the Rampart tables.

This module exists so that "is this scoped to the right owner?" is a question
with exactly one place to look. Routers never build a statement against
``environments``, ``environment_assets`` or ``environment_matches`` themselves;
they call in here, and every function takes ``owner`` as its first argument and
applies it.

The rule is deliberately mechanical rather than clever: a scoping mistake in a
system that stores somebody's attack surface is not a bug you get to fix after
someone notices.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import (
    AffectedProduct,
    Document,
    EntityLink,
    Environment,
    EnvironmentAsset,
    EnvironmentMatch,
    Vulnerability,
)
from app.services.rampart import matching

#: A single owner cannot register an unbounded inventory. The cap is a denial
#: of service control as much as a product decision: every asset multiplies the
#: work done on every CVE recomputation.
MAX_ASSETS = 500

#: How much an environment match contributes on top of the global score.
#: Stored, never computed per request — see EnvironmentMatch.exposure.
EXPOSURE = {
    matching.AFFECTED: 40,
    matching.POSSIBLY_AFFECTED: 15,
    matching.NOT_AFFECTED: 0,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------- environments
def list_environments(session: Session, owner: str) -> list[Environment]:
    return list(session.scalars(
        select(Environment).where(Environment.owner_id == owner).order_by(Environment.name)
    ))


def get_environment(session: Session, owner: str, environment_id: int) -> Environment | None:
    return session.scalar(
        select(Environment).where(Environment.owner_id == owner, Environment.id == environment_id)
    )


def default_environment(session: Session, owner: str) -> Environment:
    """The owner's environment, created on first use.

    Single-environment is the shape today; the table already supports more, so
    this is a convenience rather than a constraint baked into the schema.
    """
    existing = session.scalar(
        select(Environment).where(Environment.owner_id == owner).order_by(Environment.id).limit(1)
    )
    if existing:
        return existing
    env = Environment(owner_id=owner, name="My environment", kind="inventory")
    session.add(env)
    session.flush()
    return env


# ---------------------------------------------------------------------- assets
def list_assets(session: Session, owner: str, environment_id: int) -> list[EnvironmentAsset]:
    return list(session.scalars(
        select(EnvironmentAsset)
        .where(EnvironmentAsset.owner_id == owner, EnvironmentAsset.environment_id == environment_id)
        .order_by(EnvironmentAsset.category, EnvironmentAsset.label)
    ))


def get_asset(session: Session, owner: str, asset_id: int) -> EnvironmentAsset | None:
    return session.scalar(
        select(EnvironmentAsset).where(EnvironmentAsset.owner_id == owner, EnvironmentAsset.id == asset_id)
    )


def count_assets(session: Session, owner: str) -> int:
    return session.scalar(
        select(func.count()).select_from(EnvironmentAsset).where(EnvironmentAsset.owner_id == owner)
    ) or 0


def create_asset(session: Session, owner: str, environment_id: int, **fields) -> EnvironmentAsset:
    asset = EnvironmentAsset(owner_id=owner, environment_id=environment_id, **fields)
    session.add(asset)
    session.flush()
    return asset


def update_asset(session: Session, owner: str, asset_id: int, **fields) -> EnvironmentAsset | None:
    asset = get_asset(session, owner, asset_id)
    if asset is None:
        return None
    for key, value in fields.items():
        setattr(asset, key, value)
    asset.updated_at = _now()
    session.flush()
    return asset


def delete_asset(session: Session, owner: str, asset_id: int) -> bool:
    asset = get_asset(session, owner, asset_id)
    if asset is None:
        return False
    # The matches are removed here rather than left to ON DELETE CASCADE.
    # SQLite does not enforce foreign keys unless asked to, so relying on the
    # database would delete them in Postgres and orphan them under the test
    # suite — and an orphaned match keeps listing CVEs for equipment its owner
    # has just told us they no longer run.
    session.execute(delete(EnvironmentMatch).where(
        EnvironmentMatch.owner_id == owner, EnvironmentMatch.asset_id == asset_id
    ))
    session.delete(asset)
    session.flush()
    return True


# --------------------------------------------------------------------- matches
def list_matches(session: Session, owner: str, environment_id: int,
                 states: list[str] | None = None) -> list[EnvironmentMatch]:
    stmt = select(EnvironmentMatch).where(
        EnvironmentMatch.owner_id == owner, EnvironmentMatch.environment_id == environment_id
    )
    if states:
        stmt = stmt.where(EnvironmentMatch.state.in_(states))
    return list(session.scalars(stmt.order_by(EnvironmentMatch.exposure.desc())))


def matched_cve_ids(session: Session, owner: str, environment_id: int,
                    states: list[str] | None = None) -> list[str]:
    """The CVEs this environment touches, for joining onto the existing filters."""
    stmt = select(EnvironmentMatch.cve_id).where(
        EnvironmentMatch.owner_id == owner, EnvironmentMatch.environment_id == environment_id
    )
    stmt = stmt.where(EnvironmentMatch.state.in_(states or [matching.AFFECTED, matching.POSSIBLY_AFFECTED]))
    return list(session.scalars(stmt.distinct()))


def exposure_by_cve(session: Session, owner: str, environment_id: int, states: list[str] | None = None):
    """One exposure number per CVE, for ordering the environment's threat table.

    A CVE can match several assets; the strongest verdict is the one that
    should decide where the row sits.
    """
    stmt = select(
        EnvironmentMatch.cve_id.label("cve_id"),
        func.max(EnvironmentMatch.exposure).label("exposure"),
    ).where(
        EnvironmentMatch.owner_id == owner, EnvironmentMatch.environment_id == environment_id
    )
    stmt = stmt.where(EnvironmentMatch.state.in_(states or [matching.AFFECTED, matching.POSSIBLY_AFFECTED]))
    return stmt.group_by(EnvironmentMatch.cve_id).subquery()


def _write_matches(session: Session, owner: str, asset: EnvironmentAsset,
                   results: list[tuple[str, matching.MatchResult]]) -> int:
    now = _now()
    for cve_id, result in results:
        session.add(EnvironmentMatch(
            owner_id=owner,
            environment_id=asset.environment_id,
            asset_id=asset.id,
            cve_id=cve_id,
            state=result.state,
            method=result.method,
            confidence=result.confidence,
            evidence=result.evidence,
            exposure=EXPOSURE.get(result.state, 0),
            matched_at=now,
        ))
    session.flush()
    return len(results)


def recompute_asset(session: Session, owner: str, asset_id: int) -> int:
    """Rebuild every match for one asset. Called when an asset is added or edited."""
    asset = get_asset(session, owner, asset_id)
    if asset is None:
        return 0

    session.execute(delete(EnvironmentMatch).where(
        EnvironmentMatch.owner_id == owner, EnvironmentMatch.asset_id == asset_id
    ))

    # Narrow to the CVEs whose product line could possibly match before doing
    # any version work: the corpus is ~13k vulnerabilities and 82k product rows.
    like = f"%{matching.normalise(asset.product)}%"
    candidate_ids = set(session.scalars(
        select(AffectedProduct.cve_id).where(func.lower(AffectedProduct.product).like(like)).distinct()
    ))
    candidate_ids |= set(session.scalars(
        select(Vulnerability.cve_id).where(func.lower(Vulnerability.product).like(like)).distinct()
    ))
    if not candidate_ids:
        return 0

    results: list[tuple[str, matching.MatchResult]] = []
    for cve_id in candidate_ids:
        vuln = session.get(Vulnerability, cve_id)
        if vuln is None:
            continue
        products = list(session.scalars(
            select(AffectedProduct).where(AffectedProduct.cve_id == cve_id)
        ))
        result = matching.match_asset(asset, products, vuln)
        if result is not None:
            results.append((cve_id, result))

    return _write_matches(session, owner, asset, results)


def recompute_cve(session: Session, owner: str, cve_id: str) -> int:
    """Rebuild every match for one CVE, across all of the owner's assets.

    Hooked into ``correlation.recompute_vulnerability`` so a CVE whose products
    or KEV status just changed does not leave a stale verdict behind.
    """
    assets = list(session.scalars(select(EnvironmentAsset).where(EnvironmentAsset.owner_id == owner)))
    if not assets:
        return 0

    vuln = session.get(Vulnerability, cve_id)
    if vuln is None:
        return 0
    products = list(session.scalars(select(AffectedProduct).where(AffectedProduct.cve_id == cve_id)))

    session.execute(delete(EnvironmentMatch).where(
        EnvironmentMatch.owner_id == owner, EnvironmentMatch.cve_id == cve_id
    ))

    written = 0
    for asset in assets:
        result = matching.match_asset(asset, products, vuln)
        if result is not None:
            written += _write_matches(session, owner, asset, [(cve_id, result)])
    return written


# -------------------------------------------------------------------- reading
def documents_for(session: Session, owner: str, environment_id: int,
                  limit: int = 20) -> list[tuple[Document, list[str]]]:
    """Research and news that mention a CVE this environment touches.

    Phase 1 of the news story, and the whole of it for now: a document reaches
    an environment through the CVEs it mentions, not by naming a product.
    Extracting vendors and products from prose is a separate decision, and a
    hard one — the corpus holds 10,302 distinct vendor/product pairs, a third
    of them single words, including real products called "access", "core",
    "edge" and "go".

    Returns each document with the subset of the environment's CVEs it covers,
    so the UI can say *why* an article is here rather than just listing it.
    """
    cve_ids = matched_cve_ids(session, owner, environment_id)
    if not cve_ids:
        return []

    links = session.execute(
        select(EntityLink.subject_id, EntityLink.object_id).where(
            EntityLink.subject_type == "document",
            EntityLink.object_type == "cve",
            EntityLink.object_id.in_(cve_ids),
        )
    ).all()
    if not links:
        return []

    by_doc: dict[int, list[str]] = {}
    for subject_id, cve_id in links:
        try:
            doc_id = int(subject_id)
        except (TypeError, ValueError):
            continue
        by_doc.setdefault(doc_id, []).append(cve_id)

    docs = session.scalars(
        select(Document)
        .where(Document.id.in_(by_doc))
        .order_by(Document.published_at.desc().nullslast())
        .limit(limit)
    ).all()
    return [(d, sorted(set(by_doc.get(d.id, [])))) for d in docs]


# -------------------------------------------------------------------- catalogue
def versions_for(session: Session, vendor: str, product: str, limit: int = 60) -> list[str]:
    """Versions advisories have named for one product, newest first.

    Not a release catalogue — Asber has no such thing. These are the versions
    that appear in collected advisories, which in practice means release
    numbers from CNA listings and the fixed-in builds from CPE ranges. For
    somebody saying what they run, that is usually the list they want; for
    anything else the field stays free text.
    """
    p = matching.normalise(product)
    if not p:
        return []
    stmt = select(AffectedProduct.versions).where(
        func.lower(AffectedProduct.product) == p, AffectedProduct.versions.is_not(None)
    )
    v = matching.normalise(vendor)
    if v and v != "n/a":
        stmt = stmt.where(func.lower(AffectedProduct.vendor).in_([v, "n/a", ""]))

    found: set[str] = set()
    for raw in session.scalars(stmt):
        found.update(matching.version_tokens(raw))

    try:
        ordered = sorted(found, key=matching.version_sort_key, reverse=True)
    except ValueError:  # a token that slipped past the pattern
        ordered = sorted(found, reverse=True)
    return ordered[:limit]


def catalogue(session: Session, term: str, limit: int = 20) -> list[dict]:
    """Vendor/product pairs drawn from data already collected.

    Free text stays possible — the inventory should never be blocked by a gap
    in NVD's vocabulary — but anything picked from here is marked as catalogued
    and matches far better.

    Folded case-insensitively, because the corpus carries the same product
    under two spellings and they are not a choice. A single NVD record is read
    twice: its ``configurations`` block yields the CPE vocabulary ("google",
    "chrome") and its ``affected`` block yields the CNA's own ("Google",
    "Chrome"). For Chrome that is 470 rows against 471, covering 467 of the
    same CVEs. The matcher normalises both sides before comparing, so picking
    either one finds exactly the same vulnerabilities — offering both implied a
    difference that does not exist.

    The displayed spelling is the lowest ordinal, which prefers "Chrome" over
    "chrome" and "windows server 2019" over "windows_server_2019": in both
    cases the more readable one.
    """
    like = f"%{term.strip().lower()}%"
    rows = session.execute(
        select(
            func.min(AffectedProduct.vendor).label("vendor"),
            func.min(AffectedProduct.product).label("product"),
            func.count().label("rows"),
        )
        .where(
            func.lower(AffectedProduct.product).like(like),
            AffectedProduct.product != "",
            AffectedProduct.product != "n/a",
            AffectedProduct.vendor != "n/a",
        )
        .group_by(func.lower(AffectedProduct.vendor), func.lower(AffectedProduct.product))
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [{"vendor": v, "product": p} for v, p, _ in rows]
