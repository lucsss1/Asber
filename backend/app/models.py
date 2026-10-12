"""Unified data model. See DATABASE.md for the full description.

Design notes
------------
* ``vulnerabilities`` is the canonical CVE entity (one row per CVE, regardless
  of how many sources talk about it — see "duplicate detection").
* ``documents`` holds research, news and advisories (one row per canonical URL).
* ``exploits`` holds Exploit-DB entries and GitHub PoC repositories.
* ``attack_objects`` / ``attack_relationships`` are a local copy of MITRE ATT&CK.
* ``entity_links`` is the correlation graph. Every edge records *how* it was
  derived (method), its confidence and the source that produced it.
* ``source_references`` keeps the original URL of every piece of CVE data.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import (
    DDL,
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSONType, list: JSONType}


TZ = DateTime(timezone=True)


# ---------------------------------------------------------------------------
# Source registry & freshness
# ---------------------------------------------------------------------------
class Source(Base):
    __tablename__ = "sources"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    homepage: Mapped[str] = mapped_column(Text)
    endpoint: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(64))
    tier: Mapped[int] = mapped_column(Integer)
    method: Mapped[str] = mapped_column(String(32))
    phase: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_seconds: Mapped[int] = mapped_column(Integer)

    last_attempt: Mapped[datetime | None] = mapped_column(TZ)
    last_successful_fetch: Mapped[datetime | None] = mapped_column(TZ)
    last_status: Mapped[str | None] = mapped_column(String(32))
    last_error: Mapped[str | None] = mapped_column(Text)
    items_fetched: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[dict] = mapped_column(default=dict)  # worker cursors


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_key: Mapped[str] = mapped_column(ForeignKey("sources.key", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(TZ)
    status: Mapped[str] = mapped_column(String(32), default="running")
    items_fetched: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)


class HttpCache(Base):
    """Conditional-request validators so unchanged feeds are not re-downloaded."""

    __tablename__ = "http_cache"

    url: Mapped[str] = mapped_column(Text, primary_key=True)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)


# ---------------------------------------------------------------------------
# Vulnerabilities (canonical CVE entity)
# ---------------------------------------------------------------------------
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    vuln_status: Mapped[str | None] = mapped_column(String(64))
    published: Mapped[datetime | None] = mapped_column(TZ, index=True)
    last_modified: Mapped[datetime | None] = mapped_column(TZ)
    first_seen: Mapped[datetime] = mapped_column(TZ, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(TZ, default=utcnow, index=True)

    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_severity: Mapped[str | None] = mapped_column(String(16), index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    ssvc_exploitation: Mapped[str | None] = mapped_column(String(16))  # none | poc | active
    ssvc_automatable: Mapped[str | None] = mapped_column(String(8))
    ssvc_technical_impact: Mapped[str | None] = mapped_column(String(16))
    cwes: Mapped[list] = mapped_column(default=list)

    vendor: Mapped[str | None] = mapped_column(String(200), index=True)
    product: Mapped[str | None] = mapped_column(String(300), index=True)

    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_name: Mapped[str | None] = mapped_column(Text)
    kev_date_added: Mapped[date | None] = mapped_column(Date, index=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    kev_ransomware: Mapped[str | None] = mapped_column(String(16))
    kev_notes: Mapped[str | None] = mapped_column(Text)

    # Derived by services.correlation.recompute_vulnerability
    actively_exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_exploit: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_poc: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exploit_count: Mapped[int] = mapped_column(Integer, default=0)
    poc_count: Mapped[int] = mapped_column(Integer, default=0)
    source_count: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[list] = mapped_column(default=list)
    platforms: Mapped[list] = mapped_column(default=list)
    relevance_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    relevance_reasons: Mapped[list] = mapped_column(default=list)
    techniques: Mapped[list] = mapped_column(default=list)  # [{"id": "T1190", "method": "heuristic"}]
    last_activity_at: Mapped[datetime | None] = mapped_column(TZ, index=True)  # newest real-world signal

    nvd_fetched_at: Mapped[datetime | None] = mapped_column(TZ)
    github_checked_at: Mapped[datetime | None] = mapped_column(TZ)


class AffectedProduct(Base):
    __tablename__ = "affected_products"
    __table_args__ = (UniqueConstraint("cve_id", "vendor", "product", "cpe", name="uq_affected"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str] = mapped_column(String(200), default="")
    product: Mapped[str] = mapped_column(String(300), default="")
    cpe: Mapped[str] = mapped_column(String(400), default="")
    versions: Mapped[str | None] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(String(64))


class SourceReference(Base):
    """Provenance: every URL that contributed data about a CVE."""

    __tablename__ = "source_references"
    __table_args__ = (UniqueConstraint("cve_id", "url", name="uq_source_ref"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), index=True)
    source_key: Mapped[str] = mapped_column(String(64))
    url: Mapped[str] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text)
    ref_type: Mapped[str] = mapped_column(String(32))  # kev|nvd|cve_org|vendor_advisory|patch|exploit|mitigation|reference
    tags: Mapped[list] = mapped_column(default=list)
    published_at: Mapped[datetime | None] = mapped_column(TZ)
    collected_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)


class NvdCache(Base):
    """Raw NVD payload per CVE; avoids re-querying the same CVE repeatedly."""

    __tablename__ = "nvd_cache"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    fetched_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)
    found: Mapped[bool] = mapped_column(Boolean, default=True)
    payload: Mapped[dict] = mapped_column(default=dict)


# ---------------------------------------------------------------------------
# Exploits / PoCs
# ---------------------------------------------------------------------------
class Exploit(Base):
    __tablename__ = "exploits"
    __table_args__ = (UniqueConstraint("source_key", "external_id", name="uq_exploit"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_key: Mapped[str] = mapped_column(String(64), index=True)
    external_id: Mapped[str] = mapped_column(String(300))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(32), default="exploit")  # exploit|poc|scanner|detection|tool|repository
    platform: Mapped[str | None] = mapped_column(String(64))
    exploit_type: Mapped[str | None] = mapped_column(String(64))
    author: Mapped[str | None] = mapped_column(String(300))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    stars: Mapped[int | None] = mapped_column(Integer)
    language: Mapped[str | None] = mapped_column(String(64))
    cve_ids: Mapped[list] = mapped_column(default=list)
    tier: Mapped[int] = mapped_column(Integer, default=4)
    published_at: Mapped[datetime | None] = mapped_column(TZ, index=True)
    source_updated_at: Mapped[datetime | None] = mapped_column(TZ)
    collected_at: Mapped[datetime] = mapped_column(TZ, default=utcnow, index=True)


# ---------------------------------------------------------------------------
# Documents: research, news, advisories
# ---------------------------------------------------------------------------
class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_key: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)  # sanitized plain-text excerpt
    doc_type: Mapped[str] = mapped_column(String(32), index=True)  # research|news|advisory|repository
    tier: Mapped[int] = mapped_column(Integer)
    authors: Mapped[list] = mapped_column(default=list)
    categories: Mapped[list] = mapped_column(default=list)
    content_hash: Mapped[str] = mapped_column(String(64))
    reports_exploitation: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[datetime | None] = mapped_column(TZ, index=True)
    collected_at: Mapped[datetime] = mapped_column(TZ, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)
    extraction_version: Mapped[str | None] = mapped_column(String(64))


# Full-text search index (PostgreSQL only; SQLite falls back to LIKE)
event.listen(
    Document.__table__,
    "after_create",
    DDL(
        "CREATE INDEX IF NOT EXISTS ix_documents_fts ON documents USING gin "
        "(to_tsvector('english', coalesce(title,'') || ' ' || coalesce(summary,'')))"
    ).execute_if(dialect="postgresql"),
)


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------
class AttackObject(Base):
    __tablename__ = "attack_objects"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    # technique|tactic|group|malware|tool|campaign|mitigation|data_source|
    # data_component|detection_strategy|analytic
    obj_type: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str | None] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(300), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    aliases: Mapped[list] = mapped_column(default=list)
    platforms: Mapped[list] = mapped_column(default=list)
    tactics: Mapped[list] = mapped_column(default=list)  # tactic shortnames for techniques
    shortname: Mapped[str | None] = mapped_column(String(64))  # tactics only
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_external_id: Mapped[str | None] = mapped_column(String(32))
    url: Mapped[str | None] = mapped_column(Text)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[datetime | None] = mapped_column(TZ)
    modified: Mapped[datetime | None] = mapped_column(TZ)
    extra: Mapped[dict] = mapped_column(default=dict)


class AttackRelationship(Base):
    __tablename__ = "attack_relationships"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    relationship_type: Mapped[str] = mapped_column(String(32), index=True)
    source_ref: Mapped[str] = mapped_column(String(128), index=True)
    target_ref: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str | None] = mapped_column(Text)


# ---------------------------------------------------------------------------
# Correlation graph
# ---------------------------------------------------------------------------
class EntityLink(Base):
    """A typed, explainable edge between two entities.

    subject_type: document | exploit | vulnerability
    object_type:  cve | attack | edb
    relation:     mentions | targets | reports_exploitation | co_mentioned
    method:       explicit | regex | dictionary | co_mention | heuristic
    """

    __tablename__ = "entity_links"
    __table_args__ = (
        UniqueConstraint("subject_type", "subject_id", "object_type", "object_id", "relation", name="uq_link"),
        Index("ix_link_object", "object_type", "object_id"),
        Index("ix_link_subject", "subject_type", "subject_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(128))
    object_type: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[str] = mapped_column(String(128))
    relation: Mapped[str] = mapped_column(String(32))
    method: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    source_key: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime | None] = mapped_column(TZ, index=True)
    created_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)


# ---------------------------------------------------------------------------
# Rampart: the owner's environment
#
# An inventory is a map of somebody's attack surface, which makes it the most
# sensitive data this system holds. Every table here carries ``owner_id`` from
# the first migration rather than waiting for multi-user, so that the day a
# second owner exists no row has to be backfilled and no query has to be
# revisited: only ``api.deps.current_owner`` changes.
#
# Every read and write goes through ``services.rampart.repository``, which is
# the only module allowed to build a query against these tables.
# ---------------------------------------------------------------------------
class Environment(Base):
    """A named collection of assets belonging to one owner.

    ``kind`` exists so the roadmap's alerting watchlists are built on this
    table rather than beside it: a watchlist is an environment with a different
    kind, and alerts hang off ``environment_id``.
    """

    __tablename__ = "environments"
    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_environment_owner_name"),
        Index("ix_environment_owner", "owner_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(String(320), nullable=False)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(32), default="inventory")  # inventory|watchlist
    created_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZ, default=utcnow, onupdate=utcnow)


class EnvironmentAsset(Base):
    """One piece of software or firmware the owner runs.

    The asset is the *software*, not the box: matching happens against vendor,
    product and version, so "FortiOS 7.2.8" is the asset and "FortiGate 100F"
    is only ``hardware_model``, a label that never reaches the matcher.

    ``catalogued`` records whether vendor/product came from the catalogue built
    out of collected data or were typed by hand. Free text is allowed — the
    inventory should never be blocked by a gap in NVD's vocabulary — but it is
    marked, and the UI shows it as unmatched rather than pretending it is known.
    """

    __tablename__ = "environment_assets"
    __table_args__ = (
        Index("ix_asset_owner_environment", "owner_id", "environment_id"),
        Index("ix_asset_vendor_product", "vendor", "product"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(String(320), nullable=False)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), index=True)

    label: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(32))  # firewall|switch|storage|hypervisor|os|application|other
    vendor: Mapped[str] = mapped_column(String(200))
    product: Mapped[str] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(64))
    cpe: Mapped[str | None] = mapped_column(String(400))
    catalogued: Mapped[bool] = mapped_column(Boolean, default=False)
    hardware_model: Mapped[str | None] = mapped_column(String(120))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZ, default=utcnow, onupdate=utcnow)


class EnvironmentMatch(Base):
    """Why one asset is, or might be, affected by one CVE.

    ``not_affected`` rows are kept rather than dropped. "We checked, and the
    version you run is outside the affected range" is an answer worth showing,
    and silently hiding it would make the absence of a CVE indistinguishable
    from never having looked.

    ``exposure`` is the stored Environment-exposure factor. It mirrors
    ``vulnerabilities.relevance_score``: written when the match is computed,
    never per request, so the tables can sort and filter on it. The global
    relevance score is shared by every view and is deliberately untouched.
    """

    __tablename__ = "environment_matches"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", name="uq_environment_match"),
        Index("ix_match_owner_environment_state", "owner_id", "environment_id", "state"),
        Index("ix_match_cve", "cve_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(String(320), nullable=False)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("environment_assets.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"))

    state: Mapped[str] = mapped_column(String(24))  # affected|possibly_affected|not_affected
    method: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    evidence: Mapped[str | None] = mapped_column(Text)
    exposure: Mapped[int] = mapped_column(Integer, default=0)
    matched_at: Mapped[datetime] = mapped_column(TZ, default=utcnow)
