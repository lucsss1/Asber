"""Security regression tests, mapped to the OWASP Top 10:2025.

These cover the controls that live in the backend and are provable without a
deployment. The controls that only exist once the stack is assembled —
authentication, TLS, security headers added by the proxy — are exercised by
``scripts/security_scan.sh`` against a running deployment, because a unit test
cannot prove that the edge is configured correctly.

Run: python -m pytest tests/test_security.py -v
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models import Document, Vulnerability
from app.services import export
from app.services.sanitize import html_to_text, safe_url
from app.services.views import cve_detail
from tests.test_correlation import full_pipeline


@pytest.fixture
def client(session_maker, router, http, settings, monkeypatch):
    monkeypatch.setattr("app.config.get_settings", lambda: settings, raising=False)
    full_pipeline(router, http, session_maker, settings)
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------- A01 Broken Access Control
def test_a01_write_endpoints_reject_unknown_sources(client):
    """The only write endpoint takes a registry key, never a user-supplied target."""
    assert client.post("/api/sources/does-not-exist/run").status_code == 404
    # ...and cannot be pointed at an arbitrary URL
    assert client.post("/api/sources/http:%2F%2Fevil.com/run").status_code == 404


def test_a01_no_endpoint_accepts_a_caller_supplied_url(client):
    """Nothing in the read model fetches a URL chosen by the caller (SSRF surface)."""
    for path, params in [
        ("/api/vulnerabilities", {"q": "http://169.254.169.254/latest/meta-data/"}),
        ("/api/documents", {"q": "http://localhost:8000/api/settings"}),
        ("/api/search", {"q": "http://169.254.169.254"}),
    ]:
        r = client.get(path, params=params)
        assert r.status_code == 200
        assert "meta-data" not in r.text  # treated as a search term, never fetched


# ---------------------------------------------------------------- A02 Security Misconfiguration
def test_a02_security_headers_on_every_response(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_a02_settings_endpoint_exposes_no_secret_values(client):
    body = client.get("/api/settings").json()
    assert set(body["credentials_configured"].values()) <= {True, False}
    text = str(body).lower()
    for leak in ("secret", "password", "token=", "bearer ", "api_key="):
        assert leak not in text


def test_a02_debug_surface_is_not_enabled(client):
    """A traceback in a response body is an information leak."""
    r = client.get("/api/vulnerabilities/%00")
    assert r.status_code in (400, 404, 422)
    assert "Traceback" not in r.text and "File \"" not in r.text


# ---------------------------------------------------------------- A05 Injection
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "'; DROP TABLE vulnerabilities;--",
    "1; SELECT pg_sleep(5)--",
    "%' UNION SELECT NULL--",
    "\\'; DELETE FROM documents WHERE '1'='1",
])
def test_a05_sql_injection_is_inert(client, session, payload):
    """A successful injection would return everything; a bound parameter returns nothing."""
    everything = client.get("/api/vulnerabilities").json()["total"]
    injected = client.get("/api/vulnerabilities", params={"q": payload}).json()
    assert injected["total"] < everything
    assert session.scalars(select(Vulnerability)).all()  # nothing was dropped


def test_a05_like_wildcards_are_escaped(client):
    """A bare % must be a literal, not "match everything"."""
    everything = client.get("/api/vulnerabilities").json()["total"]
    assert client.get("/api/vulnerabilities", params={"q": "%"}).json()["total"] < everything


@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
])
def test_a05_stored_html_never_survives_ingestion(payload):
    """External HTML is reduced to text at ingestion, so it cannot be rendered later."""
    text = html_to_text(f"<p>hello {payload}</p>")
    assert "<script" not in text.lower()
    assert "onerror" not in text.lower()
    assert "<iframe" not in text.lower()
    assert "<svg" not in text.lower()


@pytest.mark.parametrize("scheme", [
    "javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "file:///etc/passwd",
    "vbscript:msgbox(1)", "jAvAsCrIpT:alert(1)",
])
def test_a05_dangerous_url_schemes_are_dropped(scheme):
    assert safe_url(scheme) is None


def test_a05_api_responses_carry_no_markup(client):
    for path in ("/api/documents", "/api/vulnerabilities", "/api/exploits"):
        body = client.get(path).text
        assert "<script" not in body and "onerror=" not in body


# ---------------------------------------------------------------- A08 Integrity failures
def test_a08_markdown_export_cannot_inject_links(client, session):
    """An attacker-controlled title must not become a clickable link in an export."""
    doc = session.scalar(select(Document).where(Document.title.like("APT28%")))
    doc.title = "Evil [click](javascript:alert(1)) <img src=x> # heading"
    session.commit()
    text = export.to_markdown(cve_detail(session, "CVE-2026-11111"))
    # Escaped brackets make it render as literal text, not a link.
    assert "[click](" not in text
    assert r"\[click\]" in text


def test_a08_csv_export_neutralises_formulas(client, session):
    doc = session.scalar(select(Document).where(Document.title.like("APT28%")))
    doc.title = "=cmd|' /c calc'!A1"
    session.commit()
    csv_text = export.to_csv(cve_detail(session, "CVE-2026-11111"))
    assert not any(line.startswith(("=", "+", "@")) for line in csv_text.splitlines())


# ---------------------------------------------------------------- A09 Logging failures
def test_a09_ingestion_failures_are_recorded(router, http, session_maker, settings, session):
    """A failed collection must be visible, not silent."""
    from app.ingestion.base import run_worker
    from app.models import IngestionRun, Source
    from app.workers.cisa_kev import CisaKevWorker
    from tests.test_workers import KEV_URL

    router.add(KEV_URL, b"boom", status=500)
    run = run_worker(CisaKevWorker(), session_maker, http, settings)
    assert run.status == "error" and run.error
    source = session.get(Source, "cisa_kev")
    assert source.last_error and source.consecutive_failures == 1
    assert session.scalars(select(IngestionRun).where(IngestionRun.status == "error")).all()


def test_a09_secrets_never_reach_the_logs(settings, caplog):
    """Settings carry SecretStr, so a stray log line cannot print a key."""
    from pydantic import SecretStr

    from app.config import Settings

    s = Settings(github_token=SecretStr("ghp_supersecretvalue"), database_url="sqlite://")
    assert "ghp_supersecretvalue" not in repr(s)
    assert "ghp_supersecretvalue" not in str(s.github_token)


# ---------------------------------------------------------------- A10 Exceptional conditions
@pytest.mark.parametrize("path,params", [
    ("/api/vulnerabilities", {"page": -1}),
    ("/api/vulnerabilities", {"page_size": 100000}),
    ("/api/vulnerabilities", {"window": "'; DROP TABLE x;--"}),
    ("/api/vulnerabilities", {"sort": "../../etc/passwd"}),
    ("/api/attack/objects", {"type": "../../etc"}),
    ("/api/detection/rules", {"sort": "../../etc/passwd"}),
    ("/api/detection/rules", {"level": "' OR '1'='1"}),
    ("/api/detection/rules", {"status": "<script>alert(1)</script>"}),
    ("/api/detection/rules/not-a-number", {}),
    ("/api/detection/rules/0", {}),
    ("/api/search", {"q": "a"}),
    ("/api/vulnerabilities/not-a-cve", {}),
    ("/api/vulnerabilities/CVE-1", {}),
])
def test_a10_malformed_input_fails_cleanly(client, path, params):
    """Rejected with a typed error, never a 500 and never a stack trace."""
    r = client.get(path, params=params)
    assert r.status_code in (400, 404, 422), f"{path} {params} -> {r.status_code}"
    assert "Traceback" not in r.text


def test_a10_oversized_query_is_rejected(client):
    assert client.get("/api/search", params={"q": "A" * 5000}).status_code == 422


def test_a10_malformed_source_payload_does_not_abort_the_run(router, http, session_maker, settings):
    """One bad record must not discard the whole collection."""
    from app.ingestion.base import run_worker
    from app.workers.cisa_kev import CisaKevWorker
    from tests.test_workers import KEV_URL

    router.add(KEV_URL, b'{"vulnerabilities": [{"cveID": "BROKEN"}, {"cveID": "also-broken"}]}')
    run = run_worker(CisaKevWorker(), session_maker, http, settings)
    assert run.status == "success" and run.items_new == 0  # skipped, not crashed


# ------------------------------------------- A09: the suite itself is offline
def test_a09_the_api_cannot_reach_the_internet_from_a_test(client):
    """An unknown CVE must 404 from the cache, never from a live lookup.

    Workers get their HTTP client injected, so a mock transport covers them.
    The API's on-demand NVD lookup built its own client in a module global and
    escaped that, which meant every request for an unknown CVE in the suite hit
    the live NVD. It broke on 2026-10-15 with no code change, when
    CVE-2026-99999 was actually assigned and the lookup started succeeding.

    If this fails, the suite has started talking to the internet again, and
    every result it reports is a statement about the world rather than about
    the code.
    """
    r = client.get("/api/vulnerabilities/CVE-2031-45678")
    assert r.status_code == 404, (
        f"expected a cache miss, got {r.status_code} — the on-demand lookup reached the network"
    )
# --------------------------------------------- A05: detection rules are inert
def test_a05_sigma_parser_never_constructs_python_objects():
    """``yaml.safe_load`` only.

    The rule corpus is third-party content pulled from a release archive. With
    ``yaml.load`` a crafted ``!!python/object/apply`` tag in any one of three
    thousand files would execute on ingest.
    """
    from app.services import sigma
    with pytest.raises(sigma.MalformedRule):
        sigma.parse_rule("id: a\ntitle: t\nlevel: !!python/object/apply:os.system ['id']\n")


def test_a05_rule_bodies_are_stored_as_text_not_evaluated():
    from app.services import sigma
    row = sigma.parse_rule(
        "id: a\ntitle: t\ndetection:\n    sel:\n        Image|endswith: '\\cmd.exe'\n    condition: sel\n")
    assert isinstance(row["detection"], str)


def test_a05_sigma_query_injection_through_a_technique_id_is_inert(client):
    """The technique filter resolves through a bound parameter, not a string."""
    r = client.get("/api/detection/rules", params={"technique": "T1190'; DROP TABLE detection_rules;--"})
    assert r.status_code == 200 and r.json()["total"] == 0


def test_a10_hostile_archive_is_refused_before_it_is_read():
    """A zip bomb must be a rejected run, not a memory incident."""
    import io
    import zipfile

    from app.services.normalize import MalformedRecord
    from app.workers.sigma import iter_rules

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(400):
            z.writestr(f"rules/{i}.yml", "x" * 200_000)
    with pytest.raises(MalformedRecord):
        list(iter_rules(buf.getvalue()))
