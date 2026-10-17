from __future__ import annotations

import json
import pathlib
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import db as db_module
from app.config import Settings, get_settings
from app.ingestion.base import sync_registry
from app.ingestion.http import HttpClient, RateLimiter
from app.services import extract

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_json(name: str):
    return json.loads(fixture(name))


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch):
    """Keep the host's own credentials out of the tests.

    ``Settings`` reads the process environment, so a developer (or a CI runner)
    who happens to export GITHUB_TOKEN would otherwise see unrelated failures.
    """
    for name in ("NVD_API_KEY", "GITHUB_TOKEN", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
                 "ABUSECH_AUTH_KEY", "DATABASE_URL", "REDIS_URL", "TRUSTED_PROXY_IPS"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings() -> Settings:
    return Settings(database_url="sqlite://", redis_url=None, nvd_api_key=None, github_token=None,
                    run_on_startup=False, nvd_initial_days=1, cors_origins="http://localhost:3000")


@pytest.fixture
def session_maker(tmp_path, settings):
    url = f"sqlite:///{tmp_path / 'asber-test.db'}"
    engine = db_module.init_engine(url)
    db_module.create_schema(engine)
    extract.reset_attack_dictionary()
    with db_module.session_scope() as session:
        sync_registry(session, settings)
    yield db_module.session_factory()
    engine.dispose()


@pytest.fixture
def session(session_maker):
    s = session_maker()
    try:
        yield s
    finally:
        s.close()


class Router:
    """Tiny deterministic HTTP mock: URL prefix -> (status, body, headers)."""

    def __init__(self):
        self.routes: list[tuple[str, object]] = []
        self.calls: list[str] = []

    def add(self, prefix: str, body: bytes | dict | str, status: int = 200, headers: dict | None = None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.routes.insert(0, (prefix, (status, body, headers or {})))

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        for prefix, (status, body, headers) in self.routes:
            if url.startswith(prefix):
                if request.headers.get("If-None-Match") and headers.get("ETag") == request.headers["If-None-Match"]:
                    return httpx.Response(304, headers=headers)
                return httpx.Response(status, content=body, headers=headers)
        return httpx.Response(404, content=b"no route")


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def http(router) -> HttpClient:
    limiter = RateLimiter(sleep=lambda _s: None, clock=lambda: 0.0)
    client = HttpClient("asber-test/1.0", timeout=5, max_retries=2, rate_limiter=limiter,
                        transport=httpx.MockTransport(router.handler), sleep=lambda _s: None)
    yield client
    client.close()


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Keep the suite offline, including the paths that build their own client.

    Every worker gets its HTTP client injected, so a test can hand it a mock
    transport. The API's on-demand NVD lookup does not: ``_api_http`` builds a
    real ``HttpClient`` in a module-level global, which no injected transport
    can reach. The suite was therefore calling the live NVD on every request
    for an unknown CVE.

    That is how ``test_cve_detail_rejects_garbage`` broke on 2026-10-15 without
    a line of code changing. It asserted that an obviously-invented id returns
    404, and CVE-2026-99999 was genuinely assigned that day -- a Linux kernel
    issue -- so the live lookup started succeeding and the endpoint answered
    200. A test whose result depends on what the world published this morning
    is not a test.

    A real client over a refusing transport rather than a stub, so the whole
    ``HttpClient`` interface stays intact: ``fetch_cve`` reaches for
    ``rate_limiter`` before it ever calls ``get``, and a hand-rolled double
    would only discover that by failing.
    """

    def refuse(request):
        raise httpx.ConnectError(f"network is disabled in tests (tried {request.url})")

    client = HttpClient("asber-test/1.0", timeout=1, max_retries=0,
                        rate_limiter=RateLimiter(sleep=lambda _s: None, clock=lambda: 0.0),
                        transport=httpx.MockTransport(refuse), sleep=lambda _s: None)
    monkeypatch.setattr("app.api.vulnerabilities._http_client", client, raising=False)
    yield
    client.close()


def kev_fixture(days_ago: tuple[int, ...] = (4, 9)) -> bytes:
    """The CISA KEV payload with its dates anchored to today.

    The fixture carried fixed dates, which meant the suite rotted with the
    calendar rather than with the code: on 2026-10-10 the older of its two
    valid entries aged out of the 30-day window and test_dashboard_overview
    started failing on a date change, two days before anybody looked.

    Entries whose ``dateAdded`` is deliberately malformed are left alone —
    the parser is supposed to survive them, and that is its own test.
    """
    payload = fixture_json("cisa_kev.json")
    today = datetime.now(timezone.utc).date()
    offsets = iter(days_ago)
    for item in payload.get("vulnerabilities", []):
        raw = item.get("dateAdded")
        try:
            datetime.strptime(str(raw), "%Y-%m-%d")
        except (TypeError, ValueError):
            continue  # malformed on purpose; leave it that way
        item["dateAdded"] = (today - timedelta(days=next(offsets, 1))).isoformat()
    return json.dumps(payload).encode()


#: RFC 822 needs English day and month names whatever the host locale is, so
#: they are spelled out rather than left to ``strftime``.
_RFC822_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_RFC822_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def exploitdb_fixture(days_ago: tuple[int, ...] = (5, 3)) -> bytes:
    """The Exploit-DB CSV with its recent rows anchored to today.

    Third instance of the same rot, found on 2026-10-16 when the 2026-09-11 row
    crossed out of the 30-day window and ``test_dashboard_overview`` lost its
    ``new_exploits`` count. The deliberately ancient row (1999) and the
    deliberately malformed one are left alone: both exist to be skipped, and
    that is what they test.
    """
    rows = fixture("exploitdb.csv").decode().splitlines()
    today = datetime.now(timezone.utc).date()
    offsets = iter(days_ago)
    out = [rows[0]]
    for row in rows[1:]:
        cols = row.split(",")
        # Only rows that are meant to be current get moved. 1999 is the "too
        # old to count" case and `bad` is the malformed-id case.
        if cols and cols[0].isdigit() and not row.startswith("9999,"):
            fresh = (today - timedelta(days=next(offsets, 1))).isoformat()
            row = re.sub(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", fresh, row)
        out.append(row)
    return ("\n".join(out) + "\n").encode()


def research_fixture(days_ago: tuple[int, ...] = (3, 2)) -> bytes:
    """The research feed with its ``pubDate`` values anchored to today.

    Same rot as ``kev_fixture`` and the same cure. The feed's two dated items
    were fixed at 14 and 15 September 2026, and ``observed_at`` on an ATT&CK
    link is inherited from the document that produced it — so on 2026-10-15
    the APT28 item, the only one carrying a technique mention, fell outside the
    30-day window and ``test_dashboard_overview`` failed on a date change
    rather than on a code change.

    The offsets keep the items in their original order, newest last, because
    one test asserts which document is the most recent.
    """
    text = fixture("feed_research.xml").decode()
    now = datetime.now(timezone.utc)
    offsets = iter(days_ago)

    def anchor(_match) -> str:
        when = now - timedelta(days=next(offsets, 1))
        return (f"<pubDate>{_RFC822_DAYS[when.weekday()]}, {when.day:02d} "
                f"{_RFC822_MONTHS[when.month - 1]} {when.year} "
                f"{when:%H:%M:%S} +0000</pubDate>")

    return re.sub(r"<pubDate>[^<]*</pubDate>", anchor, text).encode()
