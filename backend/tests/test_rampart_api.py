"""The Rampart API, its scoping, and the recomputation hooks.

SQLite, fixtures, no network — the corpus is built in the test rather than
fetched.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.deps import current_owner
from app.config import get_settings
from app.main import app
from app.db import get_db
from app.models import AffectedProduct, EnvironmentMatch, Vulnerability
from app.services import correlation
from app.services.rampart import matching, repository


@pytest.fixture
def client(session):
    app.dependency_overrides[get_db] = lambda: session
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def corpus(session):
    """Two CVEs: one whose range covers FortiOS 7.2.8, one that does not."""
    session.add_all([
        Vulnerability(cve_id="CVE-2026-0001", vendor="fortinet", product="fortios", in_kev=True),
        Vulnerability(cve_id="CVE-2026-0002", vendor="fortinet", product="fortios"),
        Vulnerability(cve_id="CVE-2026-9999", vendor="microsoft", product="windows 10"),
    ])
    session.add_all([
        AffectedProduct(cve_id="CVE-2026-0001", vendor="fortinet", product="fortios",
                        cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                        versions=">= 7.0.0 < 7.2.9", source_key="nvd"),
        AffectedProduct(cve_id="CVE-2026-0002", vendor="fortinet", product="fortios",
                        cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                        versions=">= 6.0.0 < 6.4.0", source_key="nvd"),
        AffectedProduct(cve_id="CVE-2026-9999", vendor="microsoft", product="windows 10",
                        cpe="", versions=">= 10.0 < 11.0", source_key="nvd"),
    ])
    session.commit()


def add_asset(client, **overrides):
    payload = {"label": "Edge firewall", "category": "firewall", "vendor": "fortinet",
               "product": "fortios", "version": "7.2.8", "catalogued": True}
    payload.update(overrides)
    return client.post("/api/rampart/assets", json=payload)


# ------------------------------------------------------------------ lifecycle
def test_environment_is_created_on_first_read(client):
    body = client.get("/api/rampart/environment").json()
    assert body["assets"] == []
    assert body["counts"] == {"affected": 0, "possibly_affected": 0, "not_affected": 0}


def test_adding_an_asset_matches_it_immediately(client, corpus):
    assert add_asset(client).status_code == 201
    body = client.get("/api/rampart/environment").json()
    assert len(body["assets"]) == 1
    # In range for 0001, out of range for 0002, unrelated to 9999.
    assert body["counts"]["affected"] == 1
    assert body["counts"]["not_affected"] == 1


def test_threats_are_narrowed_to_the_environment(client, corpus):
    add_asset(client)
    body = client.get("/api/rampart/threats").json()
    ids = [item["cve_id"] for item in body["items"]]
    assert ids == ["CVE-2026-0001"]          # not_affected is excluded by default
    assert "CVE-2026-9999" not in ids        # never matched at all


def test_every_row_carries_its_verdict_and_evidence(client, corpus):
    add_asset(client)
    body = client.get("/api/rampart/threats").json()
    match = body["matches"]["CVE-2026-0001"]
    assert match["state"] == matching.AFFECTED
    assert match["method"] == "cpe_version_range"
    assert "7.2.8" in match["evidence"]


def test_not_affected_is_kept_and_reachable_on_request(client, corpus):
    add_asset(client)
    body = client.get("/api/rampart/threats", params={"state": "not_affected"}).json()
    assert [i["cve_id"] for i in body["items"]] == ["CVE-2026-0002"]


def test_editing_the_version_rebuilds_the_verdict(client, corpus):
    asset_id = add_asset(client).json()["id"]
    client.patch(f"/api/rampart/assets/{asset_id}", json={
        "label": "Edge firewall", "category": "firewall", "vendor": "fortinet",
        "product": "fortios", "version": "6.2.0", "catalogued": True,
    })
    counts = client.get("/api/rampart/environment").json()["counts"]
    assert counts["affected"] == 1        # now inside 0002's range instead
    body = client.get("/api/rampart/threats").json()
    assert [i["cve_id"] for i in body["items"]] == ["CVE-2026-0002"]


def test_deleting_an_asset_removes_its_matches(client, corpus, session):
    asset_id = add_asset(client).json()["id"]
    assert client.delete(f"/api/rampart/assets/{asset_id}").status_code == 204
    assert session.query(EnvironmentMatch).count() == 0


# ----------------------------------------------------------------- validation
@pytest.mark.parametrize(
    "field, value",
    [("category", "router"), ("label", ""), ("vendor", ""), ("version", "x" * 65), ("label", "x" * 121)],
)
def test_invalid_input_is_rejected(client, field, value):
    assert add_asset(client, **{field: value}).status_code == 422


def test_control_characters_are_stripped(client, corpus):
    body = add_asset(client, label="Edge\x00 firewall\x1b").json()
    assert body["label"] == "Edge firewall"


def test_asset_limit_is_enforced(client, corpus, monkeypatch):
    monkeypatch.setattr(repository, "MAX_ASSETS", 1)
    assert add_asset(client).status_code == 201
    assert add_asset(client, label="Second").status_code == 409


def test_unknown_state_is_rejected_rather_than_ignored(client):
    assert client.get("/api/rampart/threats", params={"state": "maybe"}).status_code == 400


# ---------------------------------------------------------------------- scope
def test_another_owner_sees_nothing(client, corpus, session, monkeypatch):
    """The whole point of owner_id: a different owner gets an empty environment."""
    add_asset(client)
    assert len(client.get("/api/rampart/environment").json()["assets"]) == 1

    app.dependency_overrides[current_owner] = lambda: "someone-else"
    try:
        body = client.get("/api/rampart/environment").json()
        assert body["assets"] == []
        assert client.get("/api/rampart/threats").json()["items"] == []
    finally:
        app.dependency_overrides.pop(current_owner, None)


def test_an_asset_cannot_be_edited_across_owners(client, corpus):
    asset_id = add_asset(client).json()["id"]
    app.dependency_overrides[current_owner] = lambda: "someone-else"
    try:
        r = client.patch(f"/api/rampart/assets/{asset_id}", json={
            "label": "Stolen", "category": "firewall", "vendor": "x", "product": "y",
        })
        assert r.status_code == 404      # not 403: the other owner's asset does not exist here
        assert client.delete(f"/api/rampart/assets/{asset_id}").status_code == 404
    finally:
        app.dependency_overrides.pop(current_owner, None)


# ----------------------------------------------------------------------- hook
def test_recomputing_a_cve_refreshes_the_environment(client, corpus, session):
    add_asset(client)
    owner = get_settings().rampart_owner
    env = repository.default_environment(session, owner)

    before = {m.cve_id: m.state for m in repository.list_matches(session, owner, env.id)}
    assert before["CVE-2026-0001"] == matching.AFFECTED

    # The range widens: the asset should fall out of it.
    session.query(AffectedProduct).filter_by(cve_id="CVE-2026-0001").update(
        {"versions": ">= 1.0.0 < 2.0.0"}
    )
    session.commit()
    correlation.recompute_vulnerability(session, "CVE-2026-0001")
    session.commit()

    after = {m.cve_id: m.state for m in repository.list_matches(session, owner, env.id)}
    assert after["CVE-2026-0001"] == matching.NOT_AFFECTED


# ------------------------------------------------------------------ catalogue
def test_catalogue_suggests_from_collected_data(client, corpus):
    items = client.get("/api/rampart/catalogue", params={"q": "forti"}).json()["items"]
    assert {"vendor": "fortinet", "product": "fortios"} in items


def test_catalogue_requires_a_real_term(client):
    assert client.get("/api/rampart/catalogue", params={"q": "f"}).status_code == 422


def test_affected_outranks_a_higher_scoring_possible(client, corpus, session):
    """The page answers "what reaches me", so a confirmed hit comes first.

    CVE-2026-0003 scores higher globally but only possibly applies; the asset's
    version puts it squarely inside 0001's range.
    """
    session.add(Vulnerability(cve_id="CVE-2026-0003", vendor="fortinet", product="fortios",
                              relevance_score=99))
    session.add(AffectedProduct(cve_id="CVE-2026-0003", vendor="fortinet", product="fortios",
                                cpe="", versions="7.0.0, 7.1.0", source_key="nvd"))
    session.query(Vulnerability).filter_by(cve_id="CVE-2026-0001").update({"relevance_score": 10})
    session.commit()

    add_asset(client)
    ids = [i["cve_id"] for i in client.get("/api/rampart/threats").json()["items"]]
    assert ids[0] == "CVE-2026-0001", "the affected match must lead, despite the lower score"
    assert "CVE-2026-0003" in ids


# --------------------------------------------------------------------- export
def test_export_markdown_carries_the_reasoning(client, corpus):
    add_asset(client)
    body = client.get("/api/rampart/export", params={"format": "markdown"}).text
    assert "## Inventory" in body
    assert "CVE-2026-0001" in body
    # An export that dropped the sentence would be a list of numbers with no
    # argument attached.
    assert "falls inside the affected range" in body


def test_export_csv_neutralises_formula_injection(client, corpus):
    """The asset label is text the owner typed; a spreadsheet must not run it."""
    add_asset(client, label="=cmd|'/c calc'!A1")
    body = client.get("/api/rampart/export", params={"format": "csv"}).text
    assert "=cmd" not in body.replace("'=cmd", "")   # only the quoted form survives
    assert "'=cmd|'/c calc'!A1" in body


def test_export_json_is_machine_readable(client, corpus):
    add_asset(client)
    body = client.get("/api/rampart/export", params={"format": "json"}).json()
    assert body["assets"][0]["product"] == "fortios"
    assert any(m["state"] == matching.AFFECTED for m in body["matches"])
    assert body["generated_at"]


def test_export_rejects_an_unknown_format(client):
    assert client.get("/api/rampart/export", params={"format": "pdf"}).status_code == 400


def test_export_filename_does_not_carry_owner_text(client, corpus):
    add_asset(client)
    r = client.get("/api/rampart/export", params={"format": "csv"})
    assert r.headers["Content-Disposition"] == 'attachment; filename="rampart.csv"'


def test_export_is_scoped_to_the_owner(client, corpus):
    add_asset(client)
    app.dependency_overrides[current_owner] = lambda: "someone-else"
    try:
        body = client.get("/api/rampart/export", params={"format": "json"}).json()
        assert body["assets"] == [] and body["matches"] == []
    finally:
        app.dependency_overrides.pop(current_owner, None)
