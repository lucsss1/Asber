"""abuse.ch workers — MalwareBazaar and URLhaus, from the public CSV dumps.

Metadata only. No sample is ever downloaded, and nothing is submitted to any
scanner; ``MALWARE_DOWNLOAD_ENABLED`` stays off and is not consulted here
because this code has no path that would honour it.

The API endpoints at ``mb-api.abuse.ch`` and ``urlhaus-api.abuse.ch`` now
require an Auth-Key. The CSV dumps these read do not — verified answering 200
without one. If that changes, the run fails loudly rather than silently
storing an error page.
"""
from __future__ import annotations

import csv
import io
import logging

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.models import AttackObject, Indicator, utcnow
from app.services import indicators as ioc
from app.services.normalize import MalformedRecord
from app.services.sanitize import clip, parse_dt

log = logging.getLogger("asber.workers.abusech")

#: The dumps open with a banner of ``#`` comments before the real header.
def _rows(payload: bytes, expected: set[str]):
    text = payload.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, line in enumerate(lines):
        candidate = line.lstrip("# ").strip()
        cols = {c.strip().strip('"') for c in candidate.split(",")}
        if expected <= cols:
            header_idx = i
            break
    if header_idx is None:
        raise MalformedRecord(f"no header with {sorted(expected)} in the first {len(lines)} lines")
    header = [c.strip().strip('"') for c in lines[header_idx].lstrip("# ").split(",")]
    body = [ln for ln in lines[header_idx + 1:] if not ln.lstrip().startswith("#")]
    return csv.DictReader(io.StringIO("\n".join(body)), fieldnames=header, skipinitialspace=True)


def resolve_family(session: Session, family: str | None, cache: dict) -> str | None:
    """An ATT&CK software STIX id for a family name, when one exists.

    Looked up by name and by alias, over ``malware`` and ``tool`` only, and
    only after suffix normalisation. Most families do not resolve: the recent
    dump names 60 and 12 land, because the biggest of them -- Mirai -- is not
    in the Enterprise matrix at all. A miss is a miss, not a guess.
    """
    for key in ioc.family_keys(family):
        if key in cache:
            if cache[key]:
                return cache[key]
            continue
        stix = session.scalar(
            select(AttackObject.stix_id).where(
                AttackObject.obj_type.in_(("malware", "tool")),
                AttackObject.name.ilike(key)))
        if stix is None:
            for obj in session.scalars(select(AttackObject).where(
                    AttackObject.obj_type.in_(("malware", "tool")))):
                if any((a or "").lower() == key for a in (obj.aliases or [])):
                    stix = obj.stix_id
                    break
        cache[key] = stix
        if stix:
            return stix
    return None


class _AbuseChWorker(BaseWorker):
    """Shared upsert: both dumps are rolling windows over the same table."""

    required: set[str] = set()

    def parse(self, row: dict) -> dict | None:
        raise NotImplementedError

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        resp = ctx.http.get(ctx.source.endpoint, session=ctx.session, conditional=True,
                            defer_cache=True, max_bytes=ctx.source.max_bytes)
        if resp.not_modified:
            stats.not_modified = True
            return

        session = ctx.session
        existing = {(k, v): pk for pk, k, v in session.execute(
            select(Indicator.id, Indicator.kind, Indicator.value_norm)
            .where(Indicator.source_key == self.key)).all()}

        now = utcnow()
        cache: dict = {}
        new_rows: list[dict] = []
        seen: set[tuple] = set()
        for row in _rows(resp.content, self.required):
            stats.fetched += 1
            try:
                parsed = self.parse(row)
            except (MalformedRecord, ValueError) as exc:
                stats.malformed += 1
                if stats.malformed <= 20:
                    log.warning("skipping malformed row", extra={"source": self.key, "error": str(exc)})
                continue
            if parsed is None:
                stats.skipped += 1
                continue
            # The family is whichever candidate ATT&CK recognises. For
            # MalwareBazaar there is one, its ``signature`` field. URLhaus has
            # no family field at all -- it puts everything in ``tags``, where
            # ``zip``, ``elf`` and ``32-bit`` outnumber the family names -- so
            # taking the first tag would label most rows with a file format.
            # A tag becomes the family only by resolving.
            candidates = parsed.pop("_candidates", [])
            for candidate in candidates:
                stix = resolve_family(session, candidate, cache)
                if stix:
                    parsed["family"] = clip(candidate, 200)
                    parsed["attack_stix_id"] = stix
                    break
            else:
                parsed.setdefault("attack_stix_id", None)
            key = (parsed["kind"], parsed["value_norm"])
            if key in seen:
                continue
            seen.add(key)

            pk = existing.get(key)
            if pk is None:
                new_rows.append(parsed)
                continue
            # A rolling window re-publishes the same row with a fresher status,
            # so an update is the normal case, not the exception.
            indicator = session.get(Indicator, pk)
            for field, value in parsed.items():
                setattr(indicator, field, value)
            indicator.last_seen_at = now
            stats.updated += 1

        for i in range(0, len(new_rows), 1000):
            chunk = new_rows[i:i + 1000]
            session.execute(insert(Indicator), [
                {**r, "source_key": self.key, "tier": ctx.source.tier,
                 "last_seen_at": now, "collected_at": now} for r in chunk])
            stats.new += len(chunk)
            ctx.checkpoint(stats)

        ctx.http.store_validators(session, resp)


class MalwareBazaarWorker(_AbuseChWorker):
    """Sample metadata. The sample itself is never fetched."""

    key = "malwarebazaar"
    required = {"sha256_hash", "first_seen_utc"}

    def parse(self, row: dict) -> dict | None:
        sha256 = ioc.normalise(row.get("sha256_hash") or "")
        if ioc.classify(sha256) != ioc.SHA256:
            raise MalformedRecord(f"not a sha256: {sha256[:32]!r}")
        family = ioc.clean(row.get("signature"))
        related = {k: v for k, v in (
            ("md5", ioc.normalise(row.get("md5_hash") or "")),
            ("sha1", ioc.normalise(row.get("sha1_hash") or "")),
            ("imphash", ioc.clean(row.get("imphash"))),
        ) if v}
        return {
            "kind": ioc.SHA256,
            "value": sha256,
            "value_norm": sha256,
            "host": None,
            "family": clip(family, 200),
            "_candidates": [family] if family else [],
            "threat": "payload",
            "status": None,
            "file_type": clip(ioc.clean(row.get("file_type_guess")), 64),
            "mime_type": clip(ioc.clean(row.get("mime_type")), 120),
            "related": related,
            "tags": [],
            "reporter": clip(ioc.clean(row.get("reporter")), 120),
            "reference_url": f"https://bazaar.abuse.ch/sample/{sha256}/",
            "first_seen_at": parse_dt(row.get("first_seen_utc")),
        }


class UrlhausWorker(_AbuseChWorker):
    """Malicious URLs. The URL is stored, never requested."""

    key = "urlhaus"
    required = {"url", "dateadded"}

    def parse(self, row: dict) -> dict | None:
        url = (row.get("url") or "").strip().strip('"')
        if ioc.classify(url) != ioc.URL:
            raise MalformedRecord(f"not a url: {url[:48]!r}")
        value_norm = ioc.normalise(url)
        if len(value_norm) > 600:
            # The column is bounded; a URL longer than that is not something a
            # reader will ever paste into a lookup.
            return None
        tags = ioc.split_tags(row.get("tags"))
        return {
            "kind": ioc.URL,
            "value": url,
            "value_norm": value_norm,
            "host": clip(ioc.host_of(url), 300),
            "family": None,
            "_candidates": tags,
            "threat": clip(ioc.clean(row.get("threat")), 64),
            "status": clip(ioc.clean(row.get("url_status")) or "unknown", 32),
            "file_type": None,
            "mime_type": None,
            "related": {},
            "tags": tags,
            "reporter": clip(ioc.clean(row.get("reporter")), 120),
            "reference_url": ioc.clean(row.get("urlhaus_link")),
            "first_seen_at": parse_dt(row.get("dateadded")),
        }
