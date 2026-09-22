"""Correlation, scoring, ATT&CK mapping and export safety."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.ingestion.base import run_worker
from app.ingestion.registry import REGISTRY_BY_KEY
from app.models import AttackObject, Document, Vulnerability
from app.services import correlation, export
from app.services.scoring import ScoreInput, compute_relevance
from app.services.views import cve_detail
from app.workers.cisa_kev import CisaKevWorker
from app.workers.exploitdb import ExploitDbWorker
from app.workers.feed import FeedWorker
from app.workers.github import GithubWorker
from app.workers.nvd import NvdWorker
from tests.conftest import fixture
from tests.test_workers import ATTACK_INDEX, BUNDLE_URL, EDB_URL, KEV_URL, attack_index

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)


def full_pipeline(router, http, session_maker, settings):
    router.add(ATTACK_INDEX, attack_index())
    router.add(BUNDLE_URL, fixture("attack_mini.json"))
    router.add(KEV_URL, fixture("cisa_kev.json"))
    router.add("https://services.nvd.nist.gov/rest/json/cves/2.0", fixture("nvd_cves.json"))
    router.add(EDB_URL, fixture("exploitdb.csv"))
    router.add(REGISTRY_BY_KEY["unit42"].endpoint, fixture("feed_research.xml"))
    router.add("https://api.github.com/search/repositories", fixture("github_search.json"))
    from app.workers.mitre_attack import MitreAttackWorker

    for worker in (MitreAttackWorker(), CisaKevWorker(), NvdWorker(), ExploitDbWorker(),
                   FeedWorker("unit42"), GithubWorker()):
        run_worker(worker, session_maker, http, settings)


# ----------------------------------------------------------------- scoring
def test_score_is_explainable_and_capped():
    result = compute_relevance(ScoreInput(
        in_kev=True, active_exploitation_evidence=["CISA KEV"], ransomware=True, exploit_count=2,
        poc_count=3, threat_actors=["APT28"], tags=["rce", "auth_bypass", "privilege_escalation"],
        internet_facing=True, cvss_score=9.8, independent_sources=5,
        most_recent_signal=NOW - timedelta(days=1), affected_product_count=25), now=NOW)
    assert result.score == 100  # capped
    assert sum(r["points"] for r in result.reasons) > 100
    assert result.reasons[0]["points"] >= result.reasons[-1]["points"]  # sorted by weight
    for reason in result.reasons:
        assert reason["factor"] and reason["detail"]  # nothing hidden


def test_score_of_quiet_cve_is_low():
    result = compute_relevance(ScoreInput(cvss_score=5.0, independent_sources=1,
                                          most_recent_signal=NOW - timedelta(days=400)), now=NOW)
    assert result.score <= 10
    assert [r["factor"] for r in result.reasons] == ["CVSS severity"]


def test_recency_decays():
    def score(days):
        return compute_relevance(ScoreInput(in_kev=True, most_recent_signal=NOW - timedelta(days=days)),
                                 now=NOW).score
    assert score(1) > score(20) > score(200)


def test_ssvc_poc_is_reported_separately():
    result = compute_relevance(ScoreInput(ssvc_poc=True), now=NOW)
    detail = result.reasons[0]["detail"]
    assert detail == "CISA SSVC reports public PoC"  # not phrased as a PoC repository count


# ------------------------------------------------------------- correlation
def test_full_pipeline_correlates_one_threat(router, http, session_maker, settings, session):
    full_pipeline(router, http, session_maker, settings)
    detail = cve_detail(session, "CVE-2026-11111")

    assert detail["tracked"] and detail["overview"]["vendor"] == "Fortinet"
    assert detail["cvss"]["score"] == 9.8
    assert detail["kev"]["in_kev"] and detail["kev"]["ransomware_use"] == "Known"

    # exploitation evidence from three independent kinds of source
    kinds = {e["source"] for e in detail["exploitation"]}
    assert "CISA KEV" in kinds and "CISA SSVC (via NVD)" in kinds
    assert any("Unit 42" in k or "Palo Alto" in k for k in kinds)

    assert [e["external_id"] for e in detail["public_exploits"]] == ["52001"]
    assert detail["pocs"][0]["external_id"] == "researcher/CVE-2026-11111-PoC"
    assert detail["pocs"][0]["warning"]  # unverified-code warning present

    assert [a["name"] for a in detail["threat_actors"]] == ["APT28"]
    assert detail["threat_actors"][0]["evidence"][0]["url"].startswith("https://research.example.com")
    assert "Cobalt Strike" in [m["name"] for m in detail["malware"]]

    techniques = {t["external_id"]: t for t in detail["attack"]}
    assert "T1190" in techniques
    assert techniques["T1190"]["mapping"]["method"] == "explicit"
    assert techniques["T1190"]["detection_strategies"][0]["external_id"] == "DET0001"
    assert techniques["T1190"]["detection_strategies"][0]["analytics"][0]["log_sources"][0]["name"] == "zeek:http"
    assert techniques["T1190"]["mitigations"][0]["external_id"] == "M1051"

    # every source kept with tier and original URL
    assert all(s["url"].startswith("https://") and s["tier"] in (1, 2, 3, 4) for s in detail["sources"])
    assert {s["tier"] for s in detail["sources"]} >= {1, 2, 4}

    kinds = [e["kind"] for e in detail["timeline"]]
    assert "cve_published" in kinds and "kev_added" in kinds and "exploit" in kinds and "research" in kinds
    dates = [e["date"] for e in detail["timeline"]]
    assert dates == sorted(dates)


def test_heuristic_mapping_when_no_report_mentions_techniques(router, http, session_maker, settings, session):
    router.add(ATTACK_INDEX, attack_index())
    router.add(BUNDLE_URL, fixture("attack_mini.json"))
    router.add(KEV_URL, fixture("cisa_kev.json"))
    from app.workers.mitre_attack import MitreAttackWorker

    run_worker(MitreAttackWorker(), session_maker, http, settings)
    run_worker(CisaKevWorker(), session_maker, http, settings)

    detail = cve_detail(session, "CVE-2026-22222")  # Windows privilege escalation, no articles
    mapping = {t["external_id"]: t["mapping"] for t in detail["attack"]}
    assert mapping["T1068"]["method"] == "heuristic"
    assert "Privilege-escalation" in mapping["T1068"]["detail"]


def test_unknown_cve_returns_none(session):
    assert cve_detail(session, "CVE-1999-9999") is None


def test_document_roundup_does_not_create_actor_association(router, http, session_maker, settings, session):
    full_pipeline(router, http, session_maker, settings)
    detail = cve_detail(session, "CVE-2026-40001")  # only present in the Patch Tuesday roundup
    assert detail is not None
    assert detail["threat_actors"] == []  # low-confidence mention must not imply attribution


# ----------------------------------------------------------------- exports
def test_markdown_export_escapes_external_content(router, http, session_maker, settings, session):
    full_pipeline(router, http, session_maker, settings)
    doc = session.scalar(select(Document).where(Document.title.like("APT28%")))
    doc.title = 'Evil [click](javascript:alert(1)) <img src=x> # heading'
    session.commit()
    correlation.recompute_vulnerability(session, "CVE-2026-11111")
    session.commit()

    text = export.to_markdown(cve_detail(session, "CVE-2026-11111"))
    assert "[click](" not in text  # unescaped link syntax would be clickable
    assert r"\[click\]" in text  # brackets escaped, so it renders as literal text
    assert "\\<img" in text and "<img src=x>" not in text  # HTML neutralised by escaping
    assert "CVE-2026-11111" in text and "Threat Relevance Score" in text
    assert "## Timeline" in text and "## Sources" in text


def test_csv_export_neutralises_formulas(router, http, session_maker, settings, session):
    full_pipeline(router, http, session_maker, settings)
    doc = session.scalar(select(Document).where(Document.title.like("APT28%")))
    doc.title = "=cmd|'/c calc'!A1"
    session.commit()
    csv_text = export.to_csv(cve_detail(session, "CVE-2026-11111"))
    assert "\"'=cmd" in csv_text or "'=cmd" in csv_text
    assert not any(line.startswith("=") for line in csv_text.splitlines())


def test_json_export_is_valid(router, http, session_maker, settings, session):
    import json

    full_pipeline(router, http, session_maker, settings)
    data = json.loads(export.to_json(cve_detail(session, "CVE-2026-11111")))
    assert data["cve_id"] == "CVE-2026-11111" and data["sources"]


# -------------------------------------------------------- attack dictionary
def test_ambiguous_names_do_not_match_prose(router, http, session_maker, settings, session):
    router.add(ATTACK_INDEX, attack_index())
    router.add(BUNDLE_URL, fixture("attack_mini.json"))
    from app.workers.mitre_attack import MitreAttackWorker

    run_worker(MitreAttackWorker(), session_maker, http, settings)
    from app.services.extract import get_attack_dictionary

    d = get_attack_dictionary(session, refresh=True)
    assert {m[2] for m in d.find("APT28 deployed Cobalt Strike")} == {"APT28", "Cobalt Strike"}
    # a lowercase mention of an ambiguous word must not match a group/software name
    assert d.find("the company will update the net and page settings") == []


def test_attack_objects_have_stable_identity(session, router, http, session_maker, settings):
    router.add(ATTACK_INDEX, attack_index())
    router.add(BUNDLE_URL, fixture("attack_mini.json"))
    from app.workers.mitre_attack import MitreAttackWorker

    run_worker(MitreAttackWorker(), session_maker, http, settings)
    run_worker(MitreAttackWorker(), session_maker, http, settings)
    groups = session.scalars(select(AttackObject).where(AttackObject.obj_type == "group")).all()
    assert len(groups) == 1
    assert session.scalars(select(Vulnerability)).all() == []
