"""SigmaHQ worker — the published rule archive from the latest release.

Rules are stored as text and never executed: nothing here compiles a rule,
registers it with an engine, or runs it. The archive is read entirely in
memory, so no member is ever written to disk under a name the archive chose.

The archive is third-party content, so it is treated as hostile input rather
than as a trusted file: member count, per-member size and total uncompressed
size are all capped before anything is read, which is what stops a zip bomb
from being a memory incident.
"""
from __future__ import annotations

import io
import logging
import zipfile

from sqlalchemy import insert, select

from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.models import DetectionRule, EntityLink, utcnow
from app.services import correlation, extract, sigma
from app.services.normalize import MalformedRecord
from app.services.sanitize import parse_dt

log = logging.getLogger("asber.workers.sigma")

#: The whole corpus rather than the curated ``core`` tier. Measured on release
#: r2026-07-01: core carries 1,377 rules and 13 CVE tags, all_rules carries
#: 3,302 and 193. The curated tier loses fifteen times the CVE coverage, and
#: ``level`` and ``status`` are on every rule anyway, so the filtering the
#: tiers do by hand can be done in a query instead.
ASSET_NAME = "sigma_all_rules.zip"

# Caps on the archive, applied before any member is read.
MAX_MEMBERS = 20_000
MAX_MEMBER_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def pick_asset(release: dict) -> tuple[str, str | None, str | None]:
    """The rule archive's download URL, the release tag and its publish date."""
    for asset in release.get("assets") or []:
        if asset.get("name") == ASSET_NAME and asset.get("browser_download_url"):
            return asset["browser_download_url"], release.get("tag_name"), release.get("published_at")
    names = [a.get("name") for a in release.get("assets") or []]
    raise MalformedRecord(f"release {release.get('tag_name')!r} has no {ASSET_NAME} (assets: {names})")


def iter_rules(payload: bytes):
    """Yield ``(member_name, text)`` for each rule in the archive.

    Refuses an archive that is too large or too numerous before reading any of
    it, and skips any single member that is implausibly big for a YAML rule.
    """
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir() and i.filename.lower().endswith((".yml", ".yaml"))]
        if len(infos) > MAX_MEMBERS:
            raise MalformedRecord(f"archive declares {len(infos)} rule files (cap {MAX_MEMBERS})")
        total = sum(i.file_size for i in infos)
        if total > MAX_TOTAL_BYTES:
            raise MalformedRecord(f"archive expands to {total} bytes (cap {MAX_TOTAL_BYTES})")
        for info in infos:
            if info.file_size > MAX_MEMBER_BYTES:
                log.warning("skipping oversized archive member",
                            extra={"source": "sigma", "member": info.filename, "size": info.file_size})
                continue
            with zf.open(info) as fh:
                yield info.filename, fh.read().decode("utf-8", errors="replace")


class SigmaWorker(BaseWorker):
    key = "sigma"

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        resp = ctx.http.get(ctx.source.endpoint, session=ctx.session,
                            conditional=True, defer_cache=True)
        if resp.not_modified:
            stats.not_modified = True
            return
        url, tag, published = pick_asset(resp.json())

        # The release tag is the version: an unchanged tag means an unchanged
        # corpus, so the archive is not fetched again at all.
        if ctx.state.get("release") == tag:
            stats.not_modified = True
            stats.notes.append(f"release {tag} already ingested")
            return

        archive = ctx.http.get(url, max_bytes=ctx.source.max_bytes).content
        published_at = parse_dt(published)
        session = ctx.session
        # ATT&CK edges are keyed by STIX id everywhere else in the graph, so a
        # tag of ``attack.t1190`` has to be resolved before it can be linked —
        # otherwise the edge joins nothing and the rule is invisible on the
        # technique pages it was written for.
        technique_ids = extract.get_attack_dictionary(session).technique_ids
        existing = {ext: pk for pk, ext in session.execute(
            select(DetectionRule.id, DetectionRule.external_id)
            .where(DetectionRule.source_key == self.key)).all()}

        now = utcnow()
        new_rows: list[dict] = []
        seen: set[str] = set()
        for member, text in iter_rules(archive):
            stats.fetched += 1
            try:
                parsed = sigma.parse_rule(text)
            except sigma.MalformedRule as exc:
                stats.malformed += 1
                if stats.malformed <= 20:
                    log.warning("skipping malformed Sigma rule",
                                extra={"source": self.key, "member": member, "error": str(exc)})
                continue
            parsed["url"] = f"https://github.com/SigmaHQ/sigma/blob/{tag}/{member}"
            parsed["release"] = tag
            parsed["published_at"] = published_at
            if parsed["external_id"] in seen:
                continue  # the archive should not repeat a uuid, but it is not ours to trust
            seen.add(parsed["external_id"])

            pk = existing.get(parsed["external_id"])
            if pk is None:
                new_rows.append(parsed)
                continue
            rule = session.get(DetectionRule, pk)
            for k, v in parsed.items():
                setattr(rule, k, v)
            self._link(session, str(pk), parsed, published_at, technique_ids)
            stats.updated += 1
            stats.touched_cves.update(parsed["cve_ids"])

        for i in range(0, len(new_rows), 500):
            chunk = new_rows[i:i + 500]
            values = [{**r, "source_key": self.key, "tier": ctx.source.tier, "collected_at": now} for r in chunk]
            ids = session.execute(
                insert(DetectionRule).returning(DetectionRule.id, DetectionRule.external_id), values).all()
            by_ext = {ext: pk for pk, ext in ids}
            links: list[dict] = []
            for r in chunk:
                links.extend(self._link_rows(str(by_ext[r["external_id"]]), r, published_at, now, technique_ids))
            if links:
                session.execute(insert(EntityLink), links)
            stats.new += len(chunk)
            for r in chunk:
                stats.touched_cves.update(r["cve_ids"])
            ctx.checkpoint(stats)

        ctx.state["release"] = tag
        stats.notes.append(f"release {tag}")
        # Only remember the release once every rule in it has been stored.
        ctx.http.store_validators(session, resp)

    # -- correlation -------------------------------------------------------
    # Both edges are explicit: the rule's author wrote the tag. Nothing here is
    # inferred from prose, so the evidence is the tag itself and the confidence
    # is high.
    def _link_rows(self, subject_id: str, parsed: dict, observed_at, now, technique_ids: dict) -> list[dict]:
        rows = []
        for tid in parsed["techniques"]:
            # A technique the local ATT&CK copy does not know is skipped rather
            # than linked to a dangling id: Sigma can tag a technique that was
            # deprecated or renamed, and an edge pointing at nothing is worse
            # than no edge at all.
            stix_id = technique_ids.get(tid)
            if not stix_id:
                continue
            rows.append({"subject_type": "rule", "subject_id": subject_id, "object_type": "attack",
                         "object_id": stix_id, "relation": "detects", "method": "explicit",
                         "confidence": "high", "source_key": self.key,
                         "evidence": f"Sigma rule tagged attack.{tid.lower()}",
                         "observed_at": observed_at, "created_at": now})
        for cve in parsed["cve_ids"]:
            rows.append({"subject_type": "rule", "subject_id": subject_id, "object_type": "cve",
                         "object_id": cve, "relation": "detects", "method": "explicit",
                         "confidence": "high", "source_key": self.key,
                         "evidence": f"Sigma rule tagged cve.{cve[4:].lower()}",
                         "observed_at": observed_at, "created_at": now})
        return rows

    def _link(self, session, subject_id: str, parsed: dict, observed_at, technique_ids: dict) -> None:
        for tid in parsed["techniques"]:
            stix_id = technique_ids.get(tid)
            if not stix_id:
                continue
            correlation.link(session, subject_type="rule", subject_id=subject_id, object_type="attack",
                             object_id=stix_id, relation="detects", method="explicit", source_key=self.key,
                             confidence="high", evidence=f"Sigma rule tagged attack.{tid.lower()}",
                             observed_at=observed_at)
        for cve in parsed["cve_ids"]:
            correlation.link(session, subject_type="rule", subject_id=subject_id, object_type="cve",
                             object_id=cve, relation="detects", method="explicit", source_key=self.key,
                             confidence="high", evidence=f"Sigma rule tagged cve.{cve[4:].lower()}",
                             observed_at=observed_at)
