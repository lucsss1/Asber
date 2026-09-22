"""Redis-backed coordination (locks + manual run requests) with in-process fallback.

Redis is optional: without it the scheduler still works in a single process.
"""
from __future__ import annotations

import logging
import threading
from contextlib import contextmanager

from app.config import get_settings

log = logging.getLogger("asber.coordination")
TRIGGER_KEY = "asber:run-requests"

_local_locks: dict[str, threading.Lock] = {}
_local_triggers: set[str] = set()
_redis = None
_redis_checked = False


def redis_client():
    global _redis, _redis_checked
    if _redis_checked:
        return _redis
    _redis_checked = True
    url = get_settings().redis_url
    if not url:
        return None
    try:
        import redis

        client = redis.Redis.from_url(url, socket_timeout=5, socket_connect_timeout=5)
        client.ping()
        _redis = client
    except Exception as exc:  # noqa: BLE001
        log.warning("redis unavailable, using in-process coordination", extra={"error": str(exc)})
        _redis = None
    return _redis


@contextmanager
def source_lock(key: str, ttl_seconds: int = 3 * 3600):
    """Yields True if the lock was acquired (no overlapping runs of the same source)."""
    client = redis_client()
    if client is not None:
        lock = client.lock(f"asber:lock:{key}", timeout=ttl_seconds, blocking=False)
        acquired = lock.acquire(blocking=False)
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    lock.release()
                except Exception:  # noqa: BLE001 - lock may have expired
                    pass
        return
    lock = _local_locks.setdefault(key, threading.Lock())
    acquired = lock.acquire(blocking=False)
    try:
        yield acquired
    finally:
        if acquired:
            lock.release()


def request_run(key: str) -> bool:
    client = redis_client()
    if client is not None:
        client.sadd(TRIGGER_KEY, key)
        return True
    _local_triggers.add(key)
    return False  # only visible inside this process


def pop_run_requests() -> list[str]:
    client = redis_client()
    if client is not None:
        keys = []
        while True:
            item = client.spop(TRIGGER_KEY)
            if item is None:
                break
            keys.append(item.decode() if isinstance(item, bytes) else item)
        return keys
    keys = list(_local_triggers)
    _local_triggers.clear()
    return keys
