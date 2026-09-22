"""Polite HTTP client used by every worker.

Features: timeouts, retries with exponential backoff + jitter, Retry-After,
per-host rate limiting, conditional GET (ETag / Last-Modified), content hash
short-circuit, response size cap, scheme validation.
"""
from __future__ import annotations

import hashlib
import logging
import random
import threading
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models import HttpCache, utcnow

log = logging.getLogger("asber.http")

RETRY_STATUSES = {429, 500, 502, 503, 504}


class FetchError(Exception):
    pass


class RateLimiter:
    """Minimum interval between requests, per host. Thread-safe."""

    def __init__(self, sleep=time.sleep, clock=time.monotonic):
        self._intervals: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sleep = sleep
        self._clock = clock

    def set_interval(self, host: str, seconds: float) -> None:
        self._intervals[host] = seconds

    def wait(self, host: str) -> float:
        interval = self._intervals.get(host, 1.0)
        with self._lock:
            now = self._clock()
            last = self._last.get(host)
            delay = 0.0 if last is None else max(0.0, last + interval - now)
            self._last[host] = now + delay
        if delay:
            self._sleep(delay)
        return delay


@dataclass
class FetchResult:
    url: str
    status: int
    content: bytes
    headers: httpx.Headers
    elapsed_ms: int
    not_modified: bool = False
    validators: dict | None = None  # pending http_cache values (see HttpClient.store_validators)

    def json(self):
        import json

        return json.loads(self.content)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


def validate_url(url: str, allow_http: bool = False) -> str:
    parsed = urlparse(url)
    allowed = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme not in allowed or not parsed.netloc:
        raise FetchError(f"refusing non-https URL: {url!r}")
    return url


class HttpClient:
    def __init__(
        self,
        user_agent: str,
        timeout: float = 30.0,
        max_retries: int = 4,
        rate_limiter: RateLimiter | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep=time.sleep,
    ):
        self.max_retries = max_retries
        self.rate_limiter = rate_limiter or RateLimiter(sleep=sleep)
        self._sleep = sleep
        self._client = httpx.Client(
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"},
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            follow_redirects=True,
            max_redirects=5,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------
    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        session: Session | None = None,
        conditional: bool = False,
        defer_cache: bool = False,
        max_bytes: int = 25 * 1024 * 1024,
    ) -> FetchResult:
        """GET with retries. If ``conditional`` and a session is given, validators are
        stored in ``http_cache`` and a 304 / identical body returns ``not_modified=True``.
        With ``defer_cache`` the validators are only saved when the caller invokes
        ``store_validators`` (i.e. after the payload has been fully processed)."""
        validate_url(url)
        req_headers = dict(headers or {})
        cache: HttpCache | None = None
        if conditional and session is not None:
            cache = session.get(HttpCache, url)
            if cache:
                if cache.etag:
                    req_headers["If-None-Match"] = cache.etag
                if cache.last_modified:
                    req_headers["If-Modified-Since"] = cache.last_modified

        host = urlparse(url).netloc
        attempt = 0
        while True:
            attempt += 1
            self.rate_limiter.wait(host)
            started = time.monotonic()
            try:
                result = self._do_get(url, params, req_headers, max_bytes)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt > self.max_retries:
                    raise FetchError(f"network error after {attempt} attempts: {exc}") from exc
                self._backoff(attempt, None, url, str(exc))
                continue
            result.elapsed_ms = int((time.monotonic() - started) * 1000)

            if result.status in RETRY_STATUSES and attempt <= self.max_retries:
                self._backoff(attempt, result.headers.get("Retry-After"), url, f"HTTP {result.status}")
                continue
            if result.status == 304:
                result.not_modified = True
                return result
            if result.status >= 400:
                raise FetchError(f"HTTP {result.status} for {url}")

            if conditional and session is not None:
                digest = hashlib.sha256(result.content).hexdigest()
                if cache is not None and cache.content_sha256 == digest:
                    result.not_modified = True
                result.validators = {"url": url, "etag": result.headers.get("ETag"),
                                     "last_modified": result.headers.get("Last-Modified"),
                                     "content_sha256": digest}
                if not defer_cache:
                    self.store_validators(session, result)
            return result

    @staticmethod
    def store_validators(session: Session, result: FetchResult) -> None:
        if not result.validators:
            return
        v = result.validators
        cache = session.get(HttpCache, v["url"])
        if cache is None:
            cache = HttpCache(url=v["url"])
            session.add(cache)
        cache.etag, cache.last_modified = v["etag"], v["last_modified"]
        cache.content_sha256 = v["content_sha256"]
        cache.updated_at = utcnow()

    def _do_get(self, url, params, headers, max_bytes) -> FetchResult:
        with self._client.stream("GET", url, params=params, headers=headers) as resp:
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"response too large ({declared} bytes) for {url}")
            chunks, total = [], 0
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"response exceeded {max_bytes} bytes for {url}")
                chunks.append(chunk)
            return FetchResult(url=str(resp.url), status=resp.status_code, content=b"".join(chunks),
                               headers=resp.headers, elapsed_ms=0)

    def _backoff(self, attempt: int, retry_after: str | None, url: str, reason: str) -> None:
        delay = min(300.0, (2 ** attempt) + random.uniform(0, 1))
        if retry_after:
            try:
                delay = min(600.0, float(retry_after))
            except ValueError:
                try:
                    delay = min(600.0, max(0.0, parsedate_to_datetime(retry_after).timestamp() - time.time()))
                except (TypeError, ValueError):
                    pass
        log.warning("retrying request", extra={"url": url, "attempt": attempt, "delay_s": round(delay, 2),
                                                "reason": reason})
        self._sleep(delay)
