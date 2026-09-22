"""CISA KEV worker — official JSON feed, full catalog with conditional GET."""
from __future__ import annotations

import logging

from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.services import correlation
from app.services.normalize import MalformedRecord, parse_kev_entry

log = logging.getLogger("asber.workers.cisa_kev")


class CisaKevWorker(BaseWorker):
    key = "cisa_kev"

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        resp = ctx.http.get(ctx.source.endpoint, session=ctx.session, conditional=True,
                            max_bytes=ctx.source.max_bytes)
        if resp.not_modified:
            stats.not_modified = True
            return
        data = resp.json()
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise MalformedRecord("KEV payload missing 'vulnerabilities' list")

        ctx.state["catalog_version"] = str(data.get("catalogVersion") or "")[:32]
        for row in data["vulnerabilities"]:
            stats.fetched += 1
            try:
                parsed = parse_kev_entry(row)
            except MalformedRecord as exc:
                stats.malformed += 1
                log.warning("skipping malformed KEV row", extra={"source": self.key, "error": str(exc)})
                continue
            created, changed = correlation.apply_kev(ctx.session, parsed)
            stats.new += int(created)
            stats.updated += int(changed and not created)
            if created or changed:
                stats.touched_cves.add(parsed["cve_id"])
