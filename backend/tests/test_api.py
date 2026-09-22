"""API contract tests (FastAPI TestClient over the SQLite test database)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.test_correlation import full_pipeline


@pytest.fixture
def client(session_maker, router, http, settings, monkeypatch):
    monkeypatch.setattr("app.config.get_settings", lambda: settings, raising=False)
    full_pipeline(router, http, session_maker, settings)
    with TestClient(app) as c:
        yield c


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["sources_registered"] > 10


def test_dashboard_overview(client):
    body = client.get("/api/dashboard/overview", params={"window": "30d"}).json()
    cards = body["cards"]
    assert cards["actively_exploited"] >= 1
    assert cards["kev_added"] >= 2 and cards["new_exploits"] >= 1 and cards["new_pocs"] >= 1
    assert cards["new_research"] >= 1
    assert body["top_threats"][0]["cve_id"] == "CVE-2026-11111"
    assert body["top_threats"][0]["relevance_score"] > 50
    assert body["trending_attack"], "co-mentioned ATT&CK entities should trend"
    assert "source_health" in body and body["source_health"]["enabled"] > 0


def test_overview_rejects_bad_window(client):
    assert client.get("/api/dashboard/overview", params={"window": "banana"}).status_code == 400


@pytest.mark.parametrize("params,expected", [
    ({"kev": True}, {"CVE-2026-11111", "CVE-2026-22222"}),
    ({"exploited": True}, {"CVE-2026-11111"}),
    ({"poc": True}, {"CVE-2026-11111"}),
    ({"tag": "privilege_escalation"}, {"CVE-2026-22222"}),
    ({"platform": "network"}, {"CVE-2026-11111"}),
    ({"vendor": "fortinet"}, {"CVE-2026-11111"}),
    ({"technique": "T1190"}, {"CVE-2026-11111"}),
    ({"min_score": 90}, {"CVE-2026-11111"}),
])
def test_vulnerability_filters(client, params, expected):
    body = client.get("/api/vulnerabilities", params=params).json()
    assert {i["cve_id"] for i in body["items"]} >= expected
    if "min_score" in params:
        assert all(i["relevance_score"] >= 90 for i in body["items"])


def test_vulnerability_list_sorting_and_pagination(client):
    body = client.get("/api/vulnerabilities", params={"sort": "relevance", "page_size": 1}).json()
    assert body["page_size"] == 1 and len(body["items"]) == 1 and body["total"] >= 2
    scores = [i["relevance_score"] for i in
              client.get("/api/vulnerabilities", params={"page_size": 50}).json()["items"]]
    assert scores == sorted(scores, reverse=True)


def test_filter_by_actor(client):
    body = client.get("/api/vulnerabilities", params={"actor": "APT28"}).json()
    assert {i["cve_id"] for i in body["items"]} == {"CVE-2026-11111"}
    assert client.get("/api/vulnerabilities", params={"actor": "NoSuchGroup"}).status_code == 404


def test_cve_detail_sections(client):
    body = client.get("/api/vulnerabilities/CVE-2026-11111").json()
    for section in ("overview", "risk", "cvss", "kev", "affected_products", "exploitation", "public_exploits",
                    "pocs", "threat_actors", "campaigns", "malware", "attack", "detection",
                    "vendor_advisories", "research", "news", "timeline", "sources"):
        assert section in body, section
    assert body["risk"]["reasons"] and "not a replacement for CVSS" in body["risk"]["note"]
    assert body["detection"]["sigma"]["status"] == "phase_2"


def test_cve_detail_rejects_garbage(client):
    assert client.get("/api/vulnerabilities/not-a-cve").status_code == 400
    assert client.get("/api/vulnerabilities/CVE-2026-99999").status_code in (404, 502)


@pytest.mark.parametrize("fmt,ctype", [("json", "application/json"), ("csv", "text/csv"),
                                       ("markdown", "text/markdown")])
def test_exports(client, fmt, ctype):
    r = client.get("/api/vulnerabilities/CVE-2026-11111/export", params={"format": fmt})
    assert r.status_code == 200 and ctype in r.headers["content-type"]
    assert "CVE-2026-11111" in r.headers["content-disposition"]


def test_export_rejects_unknown_format(client):
    assert client.get("/api/vulnerabilities/CVE-2026-11111/export", params={"format": "pdf"}).status_code == 400


def test_search_across_entities(client):
    body = client.get("/api/search", params={"q": "fortios"}).json()
    assert body["vulnerabilities"] or body["documents"] or body["exploits"]
    cve = client.get("/api/search", params={"q": "CVE-2026-11111"}).json()
    assert cve["exact_cve"] == "CVE-2026-11111"
    actor = client.get("/api/search", params={"q": "Fancy Bear"}).json()  # alias search
    assert any(a["name"] == "APT28" for a in actor["attack"])


def test_exploits_and_documents_endpoints(client):
    exploits = client.get("/api/exploits", params={"kind": "poc"}).json()
    assert all(e["kind"] == "poc" for e in exploits["items"])
    assert all(e["warning"] for e in exploits["items"])  # unverified-code warning
    docs = client.get("/api/documents", params={"doc_type": "research"}).json()
    assert docs["items"] and docs["items"][0]["source"]["tier"] == 2
    apt_doc = next(d for d in docs["items"] if d["title"].startswith("APT28"))
    assert [e["name"] for e in apt_doc["entities"]], "extracted entities travel with the document"
    assert "CVE-2026-11111" in apt_doc["cves"]
    by_cve = client.get("/api/documents", params={"cve": "CVE-2026-11111"}).json()
    assert by_cve["total"] >= 1


def test_attack_endpoints(client):
    tactics = client.get("/api/attack/tactics").json()
    assert tactics["tactics"][0]["external_id"] == "TA0001"  # matrix order preserved
    assert tactics["tactics"][0]["techniques"]
    groups = client.get("/api/attack/objects", params={"type": "group"}).json()
    assert groups["items"][0]["name"] == "APT28" and groups["items"][0]["mentions"] >= 1
    detail = client.get("/api/attack/objects/G0007").json()
    assert detail["name"] == "APT28"
    assert "uses:technique" in detail["relationships"]
    assert detail["vulnerabilities"][0]["cve_id"] == "CVE-2026-11111"
    assert "co-mentions" in detail["correlation_note"]
    assert client.get("/api/attack/objects/T9999").status_code == 404
    assert client.get("/api/attack/objects", params={"type": "bogus"}).status_code == 400


def test_sources_health_and_runs(client):
    body = client.get("/api/sources").json()
    keys = {s["key"]: s for s in body["sources"]}
    assert keys["cisa_kev"]["health"] == "ok" and keys["cisa_kev"]["tier"] == 1
    assert keys["cisa_kev"]["items_fetched"] > 0
    assert keys["otx"]["health"] == "disabled" and keys["otx"]["requires_auth"]
    assert keys["sigma"]["implemented"] is False and keys["sigma"]["phase"] == 2
    runs = client.get("/api/sources/cisa_kev/runs").json()["runs"]
    assert runs and runs[0]["status"] == "success" and runs[0]["duration_ms"] is not None
    assert client.get("/api/sources/nope/runs").status_code == 404


def test_manual_trigger(client):
    assert client.post("/api/sources/cisa_kev/run").json()["queued"] is True
    assert client.post("/api/sources/sigma/run").status_code == 400  # no worker yet
    assert client.post("/api/sources/nope/run").status_code == 404


def test_settings_never_leaks_secrets(client):
    body = client.get("/api/settings").json()
    assert body["credentials_configured"] == {"NVD_API_KEY": False, "GITHUB_TOKEN": False,
                                              "VIRUSTOTAL_API_KEY": False, "OTX_API_KEY": False,
                                              "ABUSECH_AUTH_KEY": False}
    assert body["features"]["malware_download_enabled"] is False
    assert "scoring_weights" in body and body["scoring_weights"]["kev"] == 25
    text = str(body)
    assert "secret" not in text.lower() and "token=" not in text.lower()


def test_metrics(client):
    body = client.get("/api/metrics").json()
    assert body["counts"]["vulnerabilities"] >= 2 and body["counts"]["attack_objects"] > 5
    assert "cisa_kev" in body["last_runs"]


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_api_responses_contain_no_raw_html(client):
    body = client.get("/api/documents").text
    assert "<script" not in body and "onerror=" not in body
