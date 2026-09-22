"""MITRE ATT&CK Enterprise worker (STIX 2.1 bundle from mitre-attack/attack-stix-data).

1. Read ``index.json`` and compare the Enterprise collection version/modified
   with the stored cursor — skip the ~55 MB download when unchanged.
2. Download the versioned bundle and upsert objects; replace relationships.
3. Refresh the in-process name dictionary and re-link recent documents.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import timedelta

from sqlalchemy import delete, insert, select

from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.ingestion.http import FetchError
from app.models import AttackObject, AttackRelationship, Document
from app.services import correlation, extract
from app.services.normalize import MalformedRecord
from app.services.sanitize import clip, parse_dt

log = logging.getLogger("asber.workers.mitre")

TYPE_MAP = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "intrusion-set": "group",
    "malware": "malware",
    "tool": "tool",
    "campaign": "campaign",
    "course-of-action": "mitigation",
    "x-mitre-data-source": "data_source",
    "x-mitre-data-component": "data_component",
    "x-mitre-detection-strategy": "detection_strategy",
    "x-mitre-analytic": "analytic",
}
KEEP_RELATIONSHIPS = {"uses", "mitigates", "detects", "subtechnique-of", "attributed-to", "revoked-by"}
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?://[^)]+)\)")


def _naive(dt):
    return dt.replace(tzinfo=None) if dt is not None else None


def clean_description(text: str | None) -> str | None:
    if not text:
        return None
    text = _CITATION.sub("", text)
    text = _MD_LINK.sub(r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)  # ATT&CK descriptions occasionally contain inline tags
    return re.sub(r"[ \t]+", " ", text).strip()


def _mitre_ref(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
            return ref.get("external_id"), ref.get("url")
    return None, None


def parse_attack_object(obj: dict, tactic_order: dict[str, int]) -> dict | None:
    obj_type = TYPE_MAP.get(obj.get("type"))
    if not obj_type or not obj.get("id") or not obj.get("name"):
        return None
    ext_id, url = _mitre_ref(obj)
    extra: dict = {}
    if obj_type == "analytic":
        extra["log_sources"] = [
            {"data_component": r.get("x_mitre_data_component_ref"), "name": r.get("name"), "channel": r.get("channel")}
            for r in obj.get("x_mitre_log_source_references") or [] if isinstance(r, dict)
        ][:50]
        extra["mutable_elements"] = [m.get("field") for m in obj.get("x_mitre_mutable_elements") or []
                                     if isinstance(m, dict)][:20]
    elif obj_type == "data_component":
        extra["log_sources"] = [s for s in obj.get("x_mitre_log_sources") or [] if isinstance(s, dict)][:50]
    elif obj_type == "detection_strategy":
        extra["analytic_refs"] = list(obj.get("x_mitre_analytic_refs") or [])[:50]
    elif obj_type == "campaign":
        extra["first_seen"] = obj.get("first_seen")
        extra["last_seen"] = obj.get("last_seen")
    elif obj_type == "tactic":
        extra["order"] = tactic_order.get(obj["id"], 99)
    elif obj_type == "technique":
        extra["detection"] = clean_description(obj.get("x_mitre_detection"))

    is_sub = bool(obj.get("x_mitre_is_subtechnique"))
    aliases = obj.get("aliases") or obj.get("x_mitre_aliases") or []
    return {
        "stix_id": obj["id"][:128],
        "obj_type": obj_type,
        "external_id": clip(ext_id, 32),
        "name": clip(obj["name"], 300),
        "description": clean_description(obj.get("description")),
        "aliases": [a for a in aliases if isinstance(a, str) and a != obj["name"]][:50],
        "platforms": list(obj.get("x_mitre_platforms") or [])[:30],
        "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases") or []
                    if p.get("kill_chain_name") == "mitre-attack"],
        "shortname": clip(obj.get("x_mitre_shortname"), 64),
        "is_subtechnique": is_sub,
        "parent_external_id": ext_id.split(".")[0] if (is_sub and ext_id) else None,
        "url": url,
        "deprecated": bool(obj.get("x_mitre_deprecated")),
        "revoked": bool(obj.get("revoked")),
        "created": parse_dt(obj.get("created")),
        "modified": parse_dt(obj.get("modified")),
        "extra": extra,
    }


class MitreAttackWorker(BaseWorker):
    key = "mitre_attack"
    COLLECTION = "Enterprise ATT&CK"

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        index = ctx.http.get(ctx.source.endpoint, max_bytes=2 * 1024 * 1024).json()
        collection = next((c for c in index.get("collections", []) if c.get("name") == self.COLLECTION), None)
        if not collection or not collection.get("versions"):
            raise MalformedRecord("Enterprise ATT&CK collection not found in index.json")
        latest = collection["versions"][0]
        marker = f"{latest.get('version')}|{latest.get('modified')}"
        has_data = ctx.session.scalar(select(AttackObject.stix_id).limit(1)) is not None
        if ctx.state.get("version_marker") == marker and has_data:
            stats.not_modified = True
            return
        url = latest.get("url")
        if not isinstance(url, str) or not url.startswith("https://raw.githubusercontent.com/mitre-attack/"):
            raise FetchError(f"unexpected ATT&CK bundle URL: {url!r}")
        bundle = json.loads(ctx.http.get(url, max_bytes=ctx.source.max_bytes).content)
        self.import_bundle(ctx, stats, bundle)
        ctx.state["version_marker"] = marker
        ctx.state["attack_version"] = latest.get("version")
        ctx.checkpoint(stats)
        self.relink_documents(ctx, stats)

    def import_bundle(self, ctx: WorkerContext, stats: RunStats, bundle: dict) -> None:
        objects = bundle.get("objects") if isinstance(bundle, dict) else None
        if not isinstance(objects, list):
            raise MalformedRecord("STIX bundle has no 'objects' list")
        session = ctx.session

        tactic_order: dict[str, int] = {}
        for obj in objects:
            if isinstance(obj, dict) and obj.get("type") == "x-mitre-matrix":
                for i, ref in enumerate(obj.get("tactic_refs") or []):
                    tactic_order[ref] = i

        existing = dict(session.execute(select(AttackObject.stix_id, AttackObject.modified)).all())
        rels = []
        for obj in objects:
            if not isinstance(obj, dict):
                stats.malformed += 1
                continue
            if obj.get("type") == "relationship":
                if (obj.get("relationship_type") in KEEP_RELATIONSHIPS and not obj.get("revoked")
                        and not obj.get("x_mitre_deprecated") and obj.get("source_ref") and obj.get("target_ref")):
                    rels.append({"stix_id": obj["id"][:128], "relationship_type": obj["relationship_type"],
                                 "source_ref": obj["source_ref"][:128], "target_ref": obj["target_ref"][:128],
                                 "description": clean_description(obj.get("description"))})
                continue
            try:
                parsed = parse_attack_object(obj, tactic_order)
            except (TypeError, AttributeError, ValueError) as exc:
                stats.malformed += 1
                log.warning("malformed STIX object", extra={"source": self.key, "error": str(exc)})
                continue
            if parsed is None:
                continue
            stats.fetched += 1
            sid = parsed["stix_id"]
            if sid not in existing:
                session.add(AttackObject(**parsed))
                stats.new += 1
            else:
                if _naive(existing[sid]) != _naive(parsed["modified"]) or parsed["obj_type"] == "tactic":
                    session.merge(AttackObject(**parsed))
                    stats.updated += 1
        session.flush()
        # Relationships are replaced atomically within the transaction.
        session.execute(delete(AttackRelationship))
        for i in range(0, len(rels), 2000):
            session.execute(insert(AttackRelationship), rels[i:i + 2000])
        stats.notes.append(f"{len(rels)} relationships")

    def relink_documents(self, ctx: WorkerContext, stats: RunStats) -> None:
        dictionary = extract.get_attack_dictionary(ctx.session, refresh=True)
        since = ctx.now - timedelta(days=60)
        docs = ctx.session.scalars(
            select(Document).where(Document.collected_at >= since,
                                   (Document.extraction_version.is_(None))
                                   | (Document.extraction_version != dictionary.version))
            .limit(3000)
        ).all()
        for doc in docs:
            stats.touched_cves |= correlation.process_document(ctx.session, doc, doc.summary or "", dictionary)
        stats.notes.append(f"re-linked {len(docs)} documents")
