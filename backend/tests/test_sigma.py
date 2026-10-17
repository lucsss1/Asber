"""Sigma: the pure parser, and the worker that stores rules without running them."""
from __future__ import annotations

import io
import zipfile

import pytest
from sqlalchemy import func, select

from app.ingestion.base import run_worker
from app.ingestion.registry import REGISTRY_BY_KEY
from app.api.detection import resolve_technique_stix
from app.models import AttackObject, DetectionRule, EntityLink
from app.services import sigma
from app.workers.sigma import MAX_MEMBER_BYTES, MAX_TOTAL_BYTES, SigmaWorker, iter_rules, pick_asset
from app.services.normalize import MalformedRecord
from tests.conftest import fixture, fixture_json
from tests.test_workers import load_attack

RELEASE_URL = REGISTRY_BY_KEY["sigma"].endpoint
ARCHIVE_URL = "https://example.test/sigma_all_rules.zip"


@pytest.fixture
def session_with_attack(router, http, session_maker, settings, session):
    """A session whose ATT&CK copy has been loaded from the fixture bundle."""
    load_attack(router, http, session_maker, settings)
    return session


@pytest.fixture
def client_with_sigma(router, http, session_maker, settings, monkeypatch):
    """A TestClient over a database that has been through the Sigma worker."""
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setattr("app.config.get_settings", lambda: settings, raising=False)
    load_attack(router, http, session_maker, settings)
    load_sigma(router, http, session_maker, settings)
    with TestClient(app) as c:
        yield c


def load_sigma(router, http, session_maker, settings):
    router.add(RELEASE_URL, fixture_json("sigma_release.json"))
    router.add(ARCHIVE_URL, fixture("sigma_all_rules.zip"))
    return run_worker(SigmaWorker(), session_maker, http, settings)


# ------------------------------------------------------------------ parser
def test_technique_tags_become_ids_and_tactics_do_not():
    tags = ["attack.initial-access", "attack.t1190", "attack.T1059.001", "attack.execution", "car.2013-05-002"]
    # A tactic is not a technique: attack.initial-access must not become a link.
    assert sigma.techniques_from_tags(tags) == ["T1190", "T1059.001"]


def test_technique_ids_are_deduplicated_in_first_seen_order():
    assert sigma.techniques_from_tags(["attack.t1190", "attack.T1190", "attack.t1068"]) == ["T1190", "T1068"]


def test_cve_tags_are_normalised():
    assert sigma.cves_from_tags(["cve.2017-5638", "cve.2022.26134", "attack.t1190"]) == [
        "CVE-2017-5638", "CVE-2022-26134"]


def test_trailing_comment_does_not_leak_into_level():
    """``level: medium # can be raised`` is a YAML comment, not part of the value.

    Four rules in the real corpus carry one, and a naive read would store the
    whole sentence as the severity.
    """
    row = sigma.parse_rule("id: a\ntitle: t\nlevel: medium # can be raised after tuning\n")
    assert row["level"] == "medium"


def test_rule_without_id_is_malformed():
    with pytest.raises(sigma.MalformedRule):
        sigma.parse_rule("title: no id here\nlevel: high\n")


def test_rule_without_title_is_malformed():
    with pytest.raises(sigma.MalformedRule):
        sigma.parse_rule("id: 1234\nlevel: high\n")


def test_unreadable_yaml_is_malformed_not_an_exception_escape():
    with pytest.raises(sigma.MalformedRule):
        sigma.parse_rule("title: unbalanced\ntags: [attack.t1190\n")


def test_non_mapping_document_is_malformed():
    with pytest.raises(sigma.MalformedRule):
        sigma.parse_rule("- just\n- a\n- list\n")


def test_detection_body_is_stored_as_inert_text():
    row = sigma.parse_rule(
        "id: a\ntitle: t\ndetection:\n    sel:\n        CommandLine|contains: '-enc'\n    condition: sel\n")
    assert isinstance(row["detection"], str) and "condition" in row["detection"]


def test_parser_never_constructs_python_objects():
    """``yaml.safe_load`` only. A rule corpus is third-party content, and
    ``yaml.load`` would let a crafted tag build arbitrary Python."""
    hostile = "id: a\ntitle: t\nlevel: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(sigma.MalformedRule):
        sigma.parse_rule(hostile)


# ------------------------------------------------------------------ archive
def _zip(members: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_archive_reader_ignores_non_rule_members():
    payload = _zip({"rules/a.yml": "id: a\ntitle: t\n", "rules/README.md": "nope", "version.txt": "x"})
    assert [name for name, _ in iter_rules(payload)] == ["rules/a.yml"]


def test_archive_that_expands_too_far_is_refused_before_reading():
    payload = _zip({f"rules/{i}.yml": "x" * 200_000 for i in range(400)})
    with pytest.raises(MalformedRecord, match="expands to"):
        list(iter_rules(payload))


def test_oversized_member_is_skipped_not_fatal():
    payload = _zip({"rules/big.yml": "x" * (MAX_MEMBER_BYTES + 1), "rules/ok.yml": "id: a\ntitle: t\n"})
    assert [name for name, _ in iter_rules(payload)] == ["rules/ok.yml"]


def test_release_without_the_rule_archive_is_malformed():
    with pytest.raises(MalformedRecord, match="sigma_all_rules.zip"):
        pick_asset({"tag_name": "r1", "assets": [{"name": "other.zip", "browser_download_url": "u"}]})


# ------------------------------------------------------------------ worker
def test_worker_stores_rules_and_links_what_it_can_resolve(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    run = load_sigma(router, http, session_maker, settings)

    # Five YAML members: one has no id, one is unreadable. Three survive, and
    # the two that do not are counted as fetched rather than silently dropped.
    assert run.status == "success"
    assert run.items_new == 3 and run.items_fetched == 5

    rule = session.scalar(select(DetectionRule).where(DetectionRule.title.like("Potential OGNL%")))
    assert rule.external_id == "4d0af518-828e-4a04-a751-a7d03f3046ad"
    assert rule.rule_format == "sigma" and rule.status == "test" and rule.level == "high"
    assert rule.logsource == {"category": "application", "product": "jvm"}
    assert rule.techniques == ["T1190"] and rule.cve_ids == ["CVE-2017-5638"]
    assert rule.release == "r2026-07-01"
    assert rule.url.endswith("rules/web/proxy_ognl.yml")
    # The body is kept so the reader can interrogate the verdict, as text.
    assert "OgnlException" in rule.detection


def test_worker_writes_explicit_edges_for_both_tag_kinds(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    load_sigma(router, http, session_maker, settings)

    rule = session.scalar(select(DetectionRule).where(DetectionRule.title.like("Potential OGNL%")))
    links = session.scalars(select(EntityLink).where(
        EntityLink.subject_type == "rule", EntityLink.subject_id == str(rule.id))).all()

    cve = [l for l in links if l.object_type == "cve"]
    assert len(cve) == 1 and cve[0].object_id == "CVE-2017-5638"
    assert cve[0].relation == "detects" and cve[0].method == "explicit" and cve[0].confidence == "high"
    # The evidence names the tag the author wrote, so the edge can be checked.
    assert "cve.2017-5638" in cve[0].evidence

    attack = [l for l in links if l.object_type == "attack"]
    assert len(attack) == 1
    # Keyed by STIX id like every other ATT&CK edge, not by "T1190" -- an edge
    # on the bare technique id would join nothing.
    assert attack[0].object_id.startswith("attack-pattern--")


def test_unknown_technique_is_skipped_rather_than_linked_to_nothing(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    load_sigma(router, http, session_maker, settings)

    rule = session.scalar(select(DetectionRule).where(DetectionRule.title.like("Rule tagged with%")))
    assert rule.techniques == ["T9999"]  # kept on the row, because it is what upstream said
    links = session.scalars(select(EntityLink).where(
        EntityLink.subject_type == "rule", EntityLink.subject_id == str(rule.id))).all()
    assert links == []


def test_same_release_is_not_re_ingested(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    load_sigma(router, http, session_maker, settings)
    again = run_worker(SigmaWorker(), session_maker, http, settings)

    assert again.status == "not_modified" or again.items_new == 0
    assert session.scalar(select(DetectionRule.id).where(
        DetectionRule.external_id == "4d0af518-828e-4a04-a751-a7d03f3046ad")) is not None
    assert len(session.scalars(select(DetectionRule)).all()) == 3


# ------------------------------------------------------------------ API
def test_technique_filter_resolves_the_technique_not_its_mitigation(
        client_with_sigma, session):
    """ATT&CK carries the same external_id on more than one object.

    T1190 is both the technique and the course-of-action that mitigates it. A
    lookup that does not constrain ``obj_type`` resolves to the mitigation,
    which no rule points at, and the endpoint answers 200 with an empty list --
    a bug wearing the costume of "no data".
    """
    body = client_with_sigma.get("/api/detection/rules", params={"technique": "T1190"}).json()
    assert body["total"] >= 1
    assert all("T1190" in r["techniques"] for r in body["items"])


def test_t1190_is_ambiguous_in_the_fixture_so_the_guard_above_is_real(session_with_attack):
    """The ambiguity has to exist for the test above to be testing anything."""
    rows = session_with_attack.execute(select(AttackObject.obj_type, AttackObject.stix_id).where(
        func.upper(AttackObject.external_id) == "T1190")).all()
    kinds = {obj_type for obj_type, _ in rows}
    assert kinds == {"technique", "mitigation"}, f"fixture no longer reproduces the collision: {kinds}"


def test_resolution_never_returns_a_mitigation(session_with_attack):
    """M1051 exists only as a course-of-action, which makes this deterministic.

    Asking about T1190 cannot prove the fix: both rows exist, the lookup has no
    ORDER BY, and the engine picks. SQLite returns the technique while
    PostgreSQL returned the mitigation, which is exactly why the bug shipped
    green and failed in production. Asking about an id that is *only* a
    mitigation has one answer on every engine: constrained, nothing resolves
    and the input passes through; unconstrained, the mitigation comes back and
    the filter goes looking for rules that detect a mitigation.
    """
    assert resolve_technique_stix(session_with_attack, "M1051") == "M1051"


def test_resolution_finds_a_real_technique(session_with_attack):
    stix = resolve_technique_stix(session_with_attack, "T1190")
    assert stix.startswith("attack-pattern--")


def test_resolution_passes_a_stix_id_through(session_with_attack):
    assert resolve_technique_stix(session_with_attack, "attack-pattern--abc") == "attack-pattern--abc"


def test_rules_reject_an_unknown_sort(client_with_sigma):
    assert client_with_sigma.get("/api/detection/rules", params={"sort": "banana"}).status_code == 400


def test_rules_reject_an_unknown_level(client_with_sigma):
    assert client_with_sigma.get("/api/detection/rules", params={"level": "spicy"}).status_code == 400


def test_detail_carries_the_body_and_the_listing_does_not(client_with_sigma):
    listing = client_with_sigma.get("/api/detection/rules").json()
    assert listing["items"] and "detection" not in listing["items"][0]
    detail = client_with_sigma.get(f"/api/detection/rules/{listing['items'][0]['id']}").json()
    assert detail["detection"]


def test_detail_404s_for_a_rule_that_does_not_exist(client_with_sigma):
    assert client_with_sigma.get("/api/detection/rules/999999").status_code == 404


def test_overview_counts_only_cves_this_deployment_tracks(client_with_sigma):
    body = client_with_sigma.get("/api/detection/overview").json()
    assert body["rules"] == 3
    # The fixture's CVE-2017-5638 is not in the test corpus, so coverage is 0:
    # a rule tagged with a CVE nobody here tracks says nothing about this corpus.
    assert body["cves_covered"] == 0
    assert body["techniques_covered"] == 1
