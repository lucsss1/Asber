"""Generic RSS/Atom worker (Unit 42, Talos, BleepingComputer, Krebs, The Record, …).

Copyright-aware: only the title, a short sanitised excerpt (≤600 chars) and
metadata are stored. The full entry text is used transiently for entity
extraction and then discarded. The original URL is always kept.
"""
from __future__ import annotations

import hashlib
import logging

import feedparser
from sqlalchemy import select

from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.models import Document, utcnow
from app.services import correlation, extract
from app.services.normalize import MalformedRecord
from app.services.sanitize import html_to_text, parse_dt, safe_url

log = logging.getLogger("asber.workers.feed")

MAX_ENTRIES = 200
EXCERPT_CHARS = 600


def parse_feed_entries(content: bytes) -> list[dict]:
    parsed = feedparser.parse(content)
    if parsed.get("bozo") and not parsed.get("entries"):
        raise MalformedRecord(f"unparseable feed: {parsed.get('bozo_exception')}")
    out = []
    for entry in parsed.entries[:MAX_ENTRIES]:
        content_html = " ".join(c.get("value", "") for c in entry.get("content", []) if isinstance(c, dict))
        summary_html = entry.get("summary", "") or ""
        out.append({
            "url": safe_url(entry.get("link")),
            "title": html_to_text(entry.get("title"), 500),
            "summary": html_to_text(summary_html or content_html, EXCERPT_CHARS) or None,
            "full_text": html_to_text(f"{summary_html} {content_html}", 60000),
            "published_at": parse_dt(entry.get("published_parsed") or entry.get("updated_parsed")
                                     or entry.get("published") or entry.get("updated")),
            "categories": [c for c in (html_to_text(t.get("term"), 64) for t in entry.get("tags", [])
                                       if isinstance(t, dict)) if c][:20],
            "authors": [a for a in (html_to_text(x.get("name"), 120) for x in entry.get("authors", [])
                                    if isinstance(x, dict)) if a][:10],
        })
    return out


class FeedWorker(BaseWorker):
    def __init__(self, key: str):
        self.key = key

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        resp = ctx.http.get(ctx.source.endpoint, session=ctx.session, conditional=True,
                            max_bytes=ctx.source.max_bytes)
        if resp.not_modified:
            stats.not_modified = True
            return
        dictionary = extract.get_attack_dictionary(ctx.session)
        for item in parse_feed_entries(resp.content):
            stats.fetched += 1
            if not item["url"] or not item["title"]:
                stats.malformed += 1
                continue
            digest = hashlib.sha256(f"{item['title']}|{item['full_text']}".encode()).hexdigest()
            doc = ctx.session.scalar(select(Document).where(Document.url == item["url"]))
            if doc is None:
                doc = Document(
                    source_key=self.key, url=item["url"], title=item["title"], summary=item["summary"],
                    doc_type=ctx.source.doc_type or "news", tier=ctx.source.tier, authors=item["authors"],
                    categories=item["categories"], content_hash=digest,
                    published_at=item["published_at"] or ctx.now, collected_at=utcnow(),
                )
                ctx.session.add(doc)
                stats.new += 1
            elif doc.content_hash != digest:
                doc.title, doc.summary, doc.content_hash = item["title"], item["summary"], digest
                doc.categories, doc.authors, doc.updated_at = item["categories"], item["authors"], utcnow()
                stats.updated += 1
            elif doc.extraction_version == dictionary.version:
                continue
            text = f"{item['full_text']} {' '.join(item['categories'])}"
            stats.touched_cves |= correlation.process_document(ctx.session, doc, text, dictionary)
