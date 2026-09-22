"""The forwarded-IP resolution must not be spoofable by an untrusted peer."""
from __future__ import annotations

import pytest

from app.config import get_settings
from app.ratelimit import allow, client_ip


class FakeRequest:
    def __init__(self, peer: str, forwarded: str | None = None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "172.18.0.0/16")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_peer_used_when_no_proxy_configured():
    assert client_ip(FakeRequest("203.0.113.9", "1.2.3.4")) == "203.0.113.9"


def test_forwarded_header_from_untrusted_peer_is_ignored(trusted):
    # An attacker connecting directly cannot claim to be someone else.
    assert client_ip(FakeRequest("203.0.113.9", "1.2.3.4")) == "203.0.113.9"


def test_client_taken_from_trusted_proxy(trusted):
    assert client_ip(FakeRequest("172.18.0.5", "203.0.113.9")) == "203.0.113.9"


def test_forged_prefix_cannot_hide_the_real_client(trusted):
    # The attacker sends "1.2.3.4"; the proxy appends the real address. Reading
    # right to left past our own proxies lands on the real client, not the forgery.
    assert client_ip(FakeRequest("172.18.0.5", "1.2.3.4, 203.0.113.9")) == "203.0.113.9"


def test_chained_trusted_proxies_are_skipped(trusted):
    assert client_ip(FakeRequest("172.18.0.5", "203.0.113.9, 172.18.0.7")) == "203.0.113.9"


def test_limit_is_enforced_per_key():
    assert all(allow("test-a", 3) for _ in range(3))
    assert not allow("test-a", 3)
    assert allow("test-b", 3)  # a different client keeps its own budget
