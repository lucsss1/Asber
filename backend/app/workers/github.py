"""GitHub worker — targeted, rate-limited searches only.

1. Prioritised CVEs (KEV / high relevance / recent critical) not checked in the
   last ``GITHUB_RECHECK_HOURS`` → repository search for the exact CVE id in
   name/description.
2. User-configured queries (``GITHUB_EXTRA_QUERIES``).
3. Watched repositories (``GITHUB_WATCH_REPOS``) → latest releases.

Repositories are recorded as Tier 4 (unverified). Code is never cloned or run.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import timedelta

from sqlalchemy import and_, or_, select

from app.ingestion.base import BaseWorker, RunStats, WorkerContext
from app.ingestion.http import FetchError
from app.models import Document, Exploit, Vulnerability, utcnow
from app.services import correlation, extract
from app.services.sanitize import clip, html_to_text, parse_dt, safe_url

log = logging.getLogger("asber.workers.github")

API = "https://api.github.com"
HOST = "api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
DETECTION_WORDS = ("sigma", "yara", "nuclei", "detection", "detect", "hunting", "ioc", "snort", "suricata")
SCANNER_WORDS = ("scanner", "scan", "checker", "check ", "vulnerability check", "mass test")
POC_WORDS = ("exploit", "poc", "proof of concept", "proof-of-concept", "rce", "payload", "reproduc")


def classify_repo(name: str, description: str, cve_query: bool) -> str:
    text = f"{name} {description}".lower()
    if any(w in text for w in DETECTION_WORDS):
        return "detection"
    if any(w in text for w in SCANNER_WORDS):
        return "scanner"
    if any(w in text for w in POC_WORDS) or cve_query:
        return "poc"
    return "repository"


class GithubWorker(BaseWorker):
    key = "github"

    def _headers(self, ctx: WorkerContext) -> dict:
        token = ctx.settings.secret(ctx.settings.github_token)
        # Search API: 10 req/min anonymous, 30 req/min authenticated.
        ctx.http.rate_limiter.set_interval(HOST, 2.2 if token else 6.5)
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def candidates(self, ctx: WorkerContext) -> list[Vulnerability]:
        recheck = ctx.now - timedelta(hours=ctx.settings.github_recheck_hours)
        recent = ctx.now - timedelta(days=14)
        return list(ctx.session.scalars(
            select(Vulnerability)
            .where(or_(Vulnerability.github_checked_at.is_(None), Vulnerability.github_checked_at < recheck))
            .where(or_(Vulnerability.in_kev.is_(True), Vulnerability.relevance_score >= 50,
                       and_(Vulnerability.published >= recent, Vulnerability.cvss_score >= 8.0)))
            .order_by(Vulnerability.relevance_score.desc(), Vulnerability.updated_at.desc())
            .limit(ctx.settings.github_max_cves_per_run)
        ))

    def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
        headers = self._headers(ctx)
        try:
            for vuln in self.candidates(ctx):
                items = self._search(ctx, f'"{vuln.cve_id}" in:name,description', headers)
                for item in items:
                    name, desc = item.get("full_name") or "", item.get("description") or ""
                    if vuln.cve_id.lower() not in f"{name} {desc}".lower():
                        continue  # only keep repos that explicitly name the CVE
                    self._upsert_repo(ctx, stats, item, cve_query=True)
                vuln.github_checked_at = utcnow()
                stats.touched_cves.add(vuln.cve_id)
            for query in ctx.settings.github_queries[:10]:
                for item in self._search(ctx, query, headers):
                    self._upsert_repo(ctx, stats, item, cve_query=False)
        except _RateLimited as exc:
            stats.notes.append(f"stopped early: {exc}")
        for repo in ctx.settings.github_repos[:30]:
            self._watch_repo(ctx, stats, repo, headers)

    def _search(self, ctx: WorkerContext, query: str, headers: dict) -> list[dict]:
        try:
            resp = ctx.http.get(f"{API}/search/repositories", headers=headers,
                                params={"q": query[:256], "sort": "updated", "order": "desc", "per_page": 30},
                                max_bytes=5 * 1024 * 1024)
        except FetchError as exc:
            if "HTTP 403" in str(exc) or "HTTP 429" in str(exc):
                raise _RateLimited(str(exc)) from exc
            raise
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            ctx.state["rate_limited_until"] = resp.headers.get("X-RateLimit-Reset")
        data = resp.json()
        items = data.get("items") if isinstance(data, dict) else None
        return [i for i in (items or []) if isinstance(i, dict) and not i.get("fork")]

    def _upsert_repo(self, ctx: WorkerContext, stats: RunStats, item: dict, cve_query: bool) -> None:
        full_name = item.get("full_name")
        url = safe_url(item.get("html_url"))
        if not isinstance(full_name, str) or not REPO_RE.match(full_name) or not url \
                or not url.startswith("https://github.com/"):
            stats.malformed += 1
            return
        stats.fetched += 1
        desc = html_to_text(item.get("description"), 500)
        cves = extract.find_cves(f"{full_name} {desc}")
        values = dict(
            title=full_name, description=desc or None, url=url,
            kind=classify_repo(full_name, desc, cve_query), language=clip(item.get("language"), 64),
            stars=item.get("stargazers_count") if isinstance(item.get("stargazers_count"), int) else None,
            author=clip((item.get("owner") or {}).get("login"), 300), cve_ids=cves, tier=4,
            published_at=parse_dt(item.get("created_at")), source_updated_at=parse_dt(item.get("pushed_at")),
            exploit_type="github-repository", platform=None,
        )
        exploit = ctx.session.scalar(select(Exploit).where(Exploit.source_key == self.key,
                                                           Exploit.external_id == full_name))
        if exploit is None:
            exploit = Exploit(source_key=self.key, external_id=full_name, **values)
            ctx.session.add(exploit)
            ctx.session.flush()
            stats.new += 1
        else:
            changed = False
            for k, v in values.items():
                if k in ("published_at", "source_updated_at"):
                    continue
                if getattr(exploit, k) != v:
                    setattr(exploit, k, v)
                    changed = True
            exploit.source_updated_at = values["source_updated_at"]
            stats.updated += int(changed)
        for cve in cves:
            correlation.link(ctx.session, subject_type="exploit", subject_id=exploit.id, object_type="cve",
                             object_id=cve, relation="targets", method="explicit", source_key=self.key,
                             confidence="low", evidence=f"GitHub repo {full_name} names {cve}",
                             observed_at=exploit.published_at)
            stats.touched_cves.add(cve)

    def _watch_repo(self, ctx: WorkerContext, stats: RunStats, repo: str, headers: dict) -> None:
        if not REPO_RE.match(repo):
            stats.notes.append(f"ignored invalid repo name {repo!r}")
            return
        try:
            releases = ctx.http.get(f"{API}/repos/{repo}/releases", headers=headers,
                                    params={"per_page": 5}, max_bytes=5 * 1024 * 1024).json()
        except FetchError as exc:
            stats.notes.append(f"{repo}: {exc}")
            return
        for rel in releases if isinstance(releases, list) else []:
            url = safe_url(rel.get("html_url"))
            if not url:
                continue
            stats.fetched += 1
            title = f"{repo} {html_to_text(rel.get('name') or rel.get('tag_name'), 200)}".strip()
            body = html_to_text(rel.get("body"), 20000)
            digest = hashlib.sha256(f"{title}{body}".encode()).hexdigest()
            doc = ctx.session.scalar(select(Document).where(Document.url == url))
            if doc is None:
                doc = Document(source_key=self.key, url=url, title=title, summary=body[:600] or None,
                               doc_type="repository", tier=4, authors=[], categories=["github-release"],
                               content_hash=digest, published_at=parse_dt(rel.get("published_at")))
                ctx.session.add(doc)
                stats.new += 1
            elif doc.content_hash == digest:
                continue
            else:
                doc.title, doc.summary, doc.content_hash, doc.updated_at = title, body[:600] or None, digest, utcnow()
                stats.updated += 1
            stats.touched_cves |= correlation.process_document(ctx.session, doc, body)


class _RateLimited(Exception):
    pass
