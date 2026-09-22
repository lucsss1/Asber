"""End-to-end worker runs against local fixtures (no network)."""
from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from app.ingestion.base import run_worker
from app.ingestion.registry import REGISTRY_BY_KEY
from app.models import (
    AffectedProduct,
    AttackObject,
    AttackRelationship,
    Document,
    EntityLink,
    Exploit,
    IngestionRun,
    Source,
    SourceReference,
    Vulnerability,
)
from app.workers.cisa_kev import CisaKevWorker
from app.workers.exploitdb import ExploitDbWorker
from app.workers.feed import FeedWorker
from app.workers.github import GithubWorker
from app.workers.mitre_attack import MitreAttackWorker
from app.workers.nvd import NvdWorker
from tests.conftest import fixture, fixture_json

KEV_URL = REGISTRY_BY_KEY["cisa_kev"].endpoint
EDB_URL = REGISTRY_BY_KEY["exploitdb"].endpoint
ATTACK_INDEX = REGISTRY_BY_KEY["mitre_attack"].endpoint
BUNDLE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"


def attack_index() -> dict:
    return {"collections": [{"name": "Enterprise ATT&CK", "versions": [
        {"version": "19.2", "modified": "2026-08-05T21:33:58.496Z", "url": BUNDLE_URL}]}]}


def load_attack(router, http, session_maker, settings):
    router.add(ATTACK_INDEX, attack_index())
    router.add(BUNDLE_URL, fixture("attack_mini.json"))
    return run_worker(MitreAttackWorker(), session_maker, http, settings)


# ---------------------------------------------------------------- CISA KEV
def test_kev_worker_imports_and_deduplicates(router, http, session_maker, settings, session):
    router.add(KEV_URL, fixture("cisa_kev.json"), headers={"ETag": '"kev-1"'})
    run = run_worker(CisaKevWorker(), session_maker, http, settings)

    assert run.status == "success"
    assert run.items_new == 2  # the malformed third row is skipped
    vuln = session.get(Vulnerability, "CVE-2026-11111")
    assert vuln.in_kev and vuln.kev_ransomware == "Known"
    assert vuln.vendor == "Fortinet" and vuln.product == "FortiOS"
    assert "auth_bypass" in vuln.tags and "rce" in vuln.tags
    assert "network" in vuln.platforms
    assert vuln.relevance_score > 50
    factors = {r["factor"] for r in vuln.relevance_reasons}
    assert {"CISA KEV", "Active exploitation", "Ransomware association"} <= factors
    # provenance kept
    refs = session.scalars(select(SourceReference).where(SourceReference.cve_id == "CVE-2026-11111")).all()
    assert any(r.ref_type == "kev" for r in refs)
    assert any(r.ref_type == "vendor_advisory" and "fortiguard" in r.url for r in refs)

    # a second run with the same ETag must not create duplicates
    second = run_worker(CisaKevWorker(), session_maker, http, settings)
    assert second.status == "not_modified"
    assert session.scalar(select(Vulnerability.cve_id).where(Vulnerability.cve_id == "CVE-2026-11111"))
    assert len(session.scalars(select(Vulnerability)).all()) == 2


def test_kev_worker_records_failure_without_crashing(router, http, session_maker, settings, session):
    router.add(KEV_URL, b"upstream is down", status=500)
    run = run_worker(CisaKevWorker(), session_maker, http, settings)
    assert run.status == "error" and "HTTP 500" in run.error
    source = session.get(Source, "cisa_kev")
    assert source.consecutive_failures == 1 and source.last_successful_fetch is None
    # other sources keep working
    router.add(ATTACK_INDEX, attack_index())
    router.add(BUNDLE_URL, fixture("attack_mini.json"))
    assert run_worker(MitreAttackWorker(), session_maker, http, settings).status == "success"


def test_kev_worker_rejects_wrong_shape(router, http, session_maker, settings):
    router.add(KEV_URL, {"unexpected": True})
    assert run_worker(CisaKevWorker(), session_maker, http, settings).status == "error"


# ---------------------------------------------------------------- NVD
def test_nvd_incremental_and_cache(router, http, session_maker, settings, session):
    router.add("https://services.nvd.nist.gov/rest/json/cves/2.0", fixture("nvd_cves.json"))
    run = run_worker(NvdWorker(), session_maker, http, settings)

    assert run.status == "success"
    vuln = session.get(Vulnerability, "CVE-2026-11111")
    assert vuln.cvss_score == 9.8 and vuln.ssvc_exploitation == "active"
    assert vuln.actively_exploited is True  # SSVC counts as exploitation evidence
    assert session.scalars(select(AffectedProduct).where(AffectedProduct.cve_id == "CVE-2026-11111")).all()
    assert session.get(Source, "nvd").state["last_mod_cursor"]


def test_nvd_and_kev_produce_one_canonical_cve(router, http, session_maker, settings, session):
    router.add(KEV_URL, fixture("cisa_kev.json"))
    router.add("https://services.nvd.nist.gov/rest/json/cves/2.0", fixture("nvd_cves.json"))
    run_worker(CisaKevWorker(), session_maker, http, settings)
    run_worker(NvdWorker(), session_maker, http, settings)

    rows = session.scalars(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-11111")).all()
    assert len(rows) == 1
    v = rows[0]
    assert v.in_kev and v.cvss_score == 9.8  # merged, not duplicated
    assert v.source_count >= 2


# ---------------------------------------------------------------- Exploit-DB
def test_exploitdb_worker(router, http, session_maker, settings, session):
    router.add(EDB_URL, fixture("exploitdb.csv"), headers={"ETag": '"edb-1"'})
    router.add(KEV_URL, fixture("cisa_kev.json"))
    run_worker(CisaKevWorker(), session_maker, http, settings)
    run = run_worker(ExploitDbWorker(), session_maker, http, settings)

    assert run.status == "success" and run.items_new == 3  # malformed row skipped
    exploit = session.scalar(select(Exploit).where(Exploit.external_id == "52001"))
    assert exploit.url == "https://www.exploit-db.com/exploits/52001"
    assert exploit.verified and exploit.cve_ids == ["CVE-2026-11111"]
    vuln = session.get(Vulnerability, "CVE-2026-11111")
    assert vuln.has_exploit and vuln.exploit_count == 1
    assert any(r["factor"] == "Public exploit" for r in vuln.relevance_reasons)
    # re-running the identical file changes nothing
    assert run_worker(ExploitDbWorker(), session_maker, http, settings).status == "not_modified"
    assert len(session.scalars(select(Exploit)).all()) == 3


# ---------------------------------------------------------------- MITRE ATT&CK
def test_mitre_import_and_skip_when_unchanged(router, http, session_maker, settings, session):
    run = load_attack(router, http, session_maker, settings)
    assert run.status == "success"

    t1190 = session.scalar(select(AttackObject).where(AttackObject.external_id == "T1190"))
    assert t1190.obj_type == "technique" and t1190.tactics == ["initial-access"]
    assert "(Citation:" not in (t1190.description or "")
    assert session.scalar(select(AttackObject).where(AttackObject.external_id == "G0007")).aliases
    assert session.scalars(select(AttackRelationship)).all()
    # deprecated relationships are not imported
    assert not session.scalar(select(AttackRelationship).where(AttackRelationship.stix_id == "relationship--deprecated"))
    tactic = session.scalar(select(AttackObject).where(AttackObject.external_id == "TA0001"))
    assert tactic.extra["order"] == 0

    second = run_worker(MitreAttackWorker(), session_maker, http, settings)
    assert second.status == "not_modified"


def test_mitre_rejects_unexpected_bundle_url(router, http, session_maker, settings):
    router.add(ATTACK_INDEX, {"collections": [{"name": "Enterprise ATT&CK", "versions": [
        {"version": "19.2", "modified": "x", "url": "https://evil.example.com/bundle.json"}]}]})
    run = run_worker(MitreAttackWorker(), session_maker, http, settings)
    assert run.status == "error" and "unexpected ATT&CK bundle URL" in run.error


# ---------------------------------------------------------------- Feeds
def test_feed_worker_extracts_and_sanitises(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    router.add(REGISTRY_BY_KEY["unit42"].endpoint, fixture("feed_research.xml"))
    run = run_worker(FeedWorker("unit42"), session_maker, http, settings)

    assert run.status == "success" and run.items_new == 2  # entry without a link is skipped
    doc = session.scalar(select(Document).where(Document.title.like("APT28%")))
    assert doc.url == "https://research.example.com/apt28-fortios"  # tracking params stripped
    assert "<script>" not in (doc.summary or "") and "onerror" not in (doc.summary or "")
    assert doc.reports_exploitation is True
    assert doc.doc_type == "research" and doc.tier == 2

    links = session.scalars(select(EntityLink).where(EntityLink.subject_id == str(doc.id))).all()
    cve_links = {l.object_id: l for l in links if l.object_type == "cve" and l.relation == "mentions"}
    assert "CVE-2026-11111" in cve_links
    assert cve_links["CVE-2026-11111"].confidence == "high"
    assert any(l.relation == "reports_exploitation" for l in links)

    named = {session.get(AttackObject, l.object_id).name for l in links if l.object_type == "attack"}
    assert {"APT28", "Cobalt Strike", "Exploit Public-Facing Application"} <= named

    # A roundup mentioning many CVEs gets low-confidence links only
    roundup = session.scalar(select(Document).where(Document.title.like("Patch Tuesday%")))
    roundup_links = session.scalars(select(EntityLink).where(EntityLink.subject_id == str(roundup.id),
                                                             EntityLink.object_type == "cve")).all()
    assert roundup_links and all(l.confidence == "low" for l in roundup_links)
    assert not any(l.relation == "reports_exploitation" for l in roundup_links)


def test_feed_worker_survives_garbage(router, http, session_maker, settings):
    router.add(REGISTRY_BY_KEY["krebs"].endpoint, b"\x00\x01 not xml at all")
    assert run_worker(FeedWorker("krebs"), session_maker, http, settings).status == "error"


# ---------------------------------------------------------------- GitHub
def test_github_worker_filters_and_classifies(router, http, session_maker, settings, session):
    router.add(KEV_URL, fixture("cisa_kev.json"))
    run_worker(CisaKevWorker(), session_maker, http, settings)
    router.add("https://api.github.com/search/repositories", fixture("github_search.json"))
    run = run_worker(GithubWorker(), session_maker, http, settings)

    assert run.status == "success"
    repos = {e.external_id: e for e in session.scalars(select(Exploit).where(Exploit.source_key == "github"))}
    assert "researcher/CVE-2026-11111-PoC" in repos
    assert repos["researcher/CVE-2026-11111-PoC"].kind == "poc"
    assert repos["defender/sigma-rules-fortios"].kind == "detection"
    assert "someone/unrelated-tool" not in repos  # does not name the CVE
    assert "mirror/fork-of-poc" not in repos  # forks ignored
    assert all(e.tier == 4 for e in repos.values())

    vuln = session.get(Vulnerability, "CVE-2026-11111")
    assert vuln.has_poc and vuln.poc_count == 1
    assert vuln.github_checked_at is not None


def test_github_rate_limit_stops_run_gracefully(router, http, session_maker, settings, session):
    router.add(KEV_URL, fixture("cisa_kev.json"))
    run_worker(CisaKevWorker(), session_maker, http, settings)
    router.add("https://api.github.com/search/repositories", {"message": "rate limit"}, status=403)
    run = run_worker(GithubWorker(), session_maker, http, settings)
    assert run.status == "success"  # handled, not a crash


# ---------------------------------------------------------------- HTTP client
def test_http_retries_then_succeeds(router, http, session_maker, settings, session):
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, headers={"Retry-After": "0"})
        return httpx.Response(200, content=fixture("cisa_kev.json"))

    router.routes.insert(0, (KEV_URL, None))
    router.routes.pop(0)
    http._client = httpx.Client(transport=httpx.MockTransport(flaky))
    run = run_worker(CisaKevWorker(), session_maker, http, settings)
    assert run.status == "success" and calls["n"] == 3


def test_http_rejects_oversized_response(router, http, session_maker, settings):
    router.add(KEV_URL, b"x" * 5000)
    with pytest.raises(Exception):
        http.get(KEV_URL, max_bytes=100)


def test_run_history_recorded(router, http, session_maker, settings, session):
    router.add(KEV_URL, fixture("cisa_kev.json"))
    run_worker(CisaKevWorker(), session_maker, http, settings)
    runs = session.scalars(select(IngestionRun).where(IngestionRun.source_key == "cisa_kev")).all()
    assert len(runs) == 1
    assert runs[0].duration_ms is not None and runs[0].finished_at is not None
    source = session.get(Source, "cisa_kev")
    assert source.last_successful_fetch is not None and source.last_status == "success"


def test_registry_endpoints_are_https_and_documented():
    for sdef in REGISTRY_BY_KEY.values():
        assert sdef.endpoint.startswith("https://"), sdef.key
        assert sdef.tier in (1, 2, 3, 4) and sdef.interval >= 900
        assert sdef.source_type and sdef.category
        if sdef.requires_auth:
            assert sdef.auth_env, sdef.key


def test_json_fixture_shapes_match_registry():
    # guards against fixtures drifting from what the workers expect
    assert "vulnerabilities" in fixture_json("cisa_kev.json")
    assert "items" in fixture_json("github_search.json")
    assert json.loads(fixture("attack_mini.json"))["type"] == "bundle"
