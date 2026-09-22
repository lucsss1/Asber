from __future__ import annotations

import json
import pathlib

import httpx
import pytest

from app import db as db_module
from app.config import Settings
from app.ingestion.base import sync_registry
from app.ingestion.http import HttpClient, RateLimiter
from app.services import extract

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_json(name: str):
    return json.loads(fixture(name))


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
