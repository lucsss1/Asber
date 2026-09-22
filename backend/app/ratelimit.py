"""Request rate limiting.

Two problems with a naive limiter behind a reverse proxy:

* ``request.client.host`` is the proxy, so every client shares one bucket;
* trusting ``X-Forwarded-For`` blindly lets anyone forge an identity and get an
  unlimited number of buckets.

So the peer address is only replaced by a forwarded one when the peer itself is
a configured trusted proxy, and the counter lives in Redis so that it survives a
restart and is shared by every worker process.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict, deque

from app.config import get_settings
from app.ingestion.coordination import redis_client

log = logging.getLogger("asber.ratelimit")

_local: dict[str, deque] = defaultdict(deque)


def _networks() -> list[ipaddress._BaseNetwork]:
    out = []
    for entry in get_settings().trusted_proxy_list:
        try:
            out.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("ignoring invalid TRUSTED_PROXY_IPS entry", extra={"entry": entry})
    return out


def _trusted(addr: str, nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in nets)


def client_ip(request) -> str:
    """The real client address, or the peer when no trusted proxy is in front."""
    peer = request.client.host if request.client else "unknown"
    nets = _networks()
    if not nets or not _trusted(peer, nets):
        return peer
    forwarded = request.headers.get("x-forwarded-for", "")
    # Walk right to left past our own proxies; the first untrusted hop is the client.
    for candidate in reversed([p.strip() for p in forwarded.split(",") if p.strip()]):
        if not _trusted(candidate, nets):
            return candidate
    return peer


def allow(key: str, limit: int) -> bool:
    """Consume one token for ``key``. False when the per-minute limit is spent."""
    client = redis_client()
    if client is not None:
        try:
            bucket = f"asber:rl:{key}:{int(time.time() // 60)}"
            count = client.incr(bucket)
            if count == 1:
                client.expire(bucket, 120)
            return count <= limit
        except Exception as exc:  # noqa: BLE001  (never fail a request on Redis trouble)
            log.warning("redis rate limit unavailable, using in-process", extra={"error": str(exc)})
    now = time.monotonic()
    hits = _local[key]
    while hits and now - hits[0] > 60:
        hits.popleft()
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True
