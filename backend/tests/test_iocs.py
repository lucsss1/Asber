"""Indicators: the pure normalisation, the two abuse.ch workers, and the lookup."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.ingestion.base import run_worker
from app.ingestion.registry import REGISTRY_BY_KEY
from app.main import app
from app.models import Indicator
from app.services import indicators as ioc
from app.workers.abusech import MalwareBazaarWorker, UrlhausWorker, _rows
from app.services.normalize import MalformedRecord
from tests.conftest import abusech_fixture
from tests.test_workers import load_attack

MB_URL = REGISTRY_BY_KEY["malwarebazaar"].endpoint
UH_URL = REGISTRY_BY_KEY["urlhaus"].endpoint

SHA256 = "aaaa0497af6033669821a65fc491f172e2b830c73a1b15994b7b68f57364fc27"
MD5 = "b12b18b455aa4dbc570e9e3dd205afe4"


def load_iocs(router, http, session_maker, settings):
    router.add(MB_URL, abusech_fixture("malwarebazaar.csv"))
    router.add(UH_URL, abusech_fixture("urlhaus.csv"))
    return (run_worker(MalwareBazaarWorker(), session_maker, http, settings),
            run_worker(UrlhausWorker(), session_maker, http, settings))


@pytest.fixture
def client_with_iocs(router, http, session_maker, settings, monkeypatch):
    monkeypatch.setattr("app.config.get_settings", lambda: settings, raising=False)
    load_attack(router, http, session_maker, settings)
    load_iocs(router, http, session_maker, settings)
    with TestClient(app) as c:
        yield c


# ------------------------------------------------------------ classification
@pytest.mark.parametrize("value,expected", [
    (SHA256, "sha256"),
    (MD5, "md5"),
    ("e05a799fc34a648cfe6d31238cda1f63fd0f1331", "sha1"),
    ("http://evil.example.test/a", "url"),
    ("evil.example.test", "domain"),
    ("198.51.100.7", "ipv4"),
    ("  " + SHA256.upper() + "  ", "sha256"),
])
def test_classify_recognises_each_kind(value, expected):
    assert ioc.classify(value) == expected


@pytest.mark.parametrize("value", ["", "nope", "999.999.999.999", "no spaces here", "a" * 63])
def test_classify_rejects_what_is_not_an_indicator(value):
    assert ioc.classify(value) is None


def test_host_is_extracted_from_a_url_without_port_or_credentials():
    assert ioc.host_of("http://user:pw@evil.example.test:8080/a/b") == "evil.example.test"


def test_host_of_a_bare_domain_is_itself():
    assert ioc.host_of("Evil.Example.Test") == "evil.example.test"


def test_host_of_something_that_is_not_a_host_is_none():
    assert ioc.host_of(SHA256) is None


# ---------------------------------------------------------- family matching
def test_family_keys_strip_a_suffix_the_feed_added():
    """ATT&CK carries Remcos; the feed writes RemcosRAT."""
    assert ioc.family_keys("RemcosRAT") == ["remcosrat", "remcos"]


def test_family_keys_leave_a_name_that_needs_no_stripping():
    assert ioc.family_keys("Vidar") == ["vidar"]


def test_a_file_format_is_never_a_family():
    """``PS1`` is a real ATT&CK malware id (S0613), and also the extension
    URLhaus tags every PowerShell script with. On the recent dump that single
    collision produced 142 of 675 matches, a fifth of them wrong."""
    assert ioc.family_keys("ps1") == []
    assert ioc.family_keys("ZIP") == []
    assert ioc.family_keys("32-bit") == []


def test_placeholders_are_not_values():
    for placeholder in ("n/a", "None", "unknown", "-", ""):
        assert ioc.clean(placeholder) is None


# --------------------------------------------------------------- the dumps
def test_rows_skips_the_banner_and_finds_the_commented_header():
    rows = list(_rows(abusech_fixture("urlhaus.csv"), {"url", "dateadded"}))
    assert len(rows) == 4 and rows[0]["url"].startswith("http://")


def test_a_dump_without_the_expected_header_is_malformed():
    with pytest.raises(MalformedRecord, match="no header"):
        list(_rows(b"# banner\nsomething,else\n1,2\n", {"url", "dateadded"}))


# -------------------------------------------------------------- the workers
def test_malwarebazaar_stores_metadata_and_skips_a_bad_hash(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    mb, _ = load_iocs(router, http, session_maker, settings)

    assert mb.status == "success" and mb.items_new == 3  # the fourth has no valid sha256
    row = session.scalar(select(Indicator).where(Indicator.value_norm == SHA256))
    assert row.kind == "sha256" and row.source_key == "malwarebazaar"
    assert row.family == "Mirai" and row.file_type == "elf"
    assert row.related == {"md5": MD5, "sha1": "e05a799fc34a648cfe6d31238cda1f63fd0f1331"}
    assert row.reference_url.endswith(f"/sample/{SHA256}/")


def test_urlhaus_stores_the_host_separately(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    _, uh = load_iocs(router, http, session_maker, settings)

    assert uh.status == "success" and uh.items_new == 3  # "notaurl" is skipped
    rows = session.scalars(select(Indicator).where(Indicator.host == "evil.example.test")).all()
    assert len(rows) == 2, "both URLs on that host must be findable by the host alone"
    assert {r.status for r in rows} == {"online", "offline"}


def test_a_format_tag_does_not_become_the_family(router, http, session_maker, settings, session):
    """The ps1-tagged row must take RemcosRAT, not PS1."""
    load_attack(router, http, session_maker, settings)
    load_iocs(router, http, session_maker, settings)

    row = session.scalar(select(Indicator).where(Indicator.value_norm.like("%payload.ps1")))
    assert row.family != "ps1"
    assert "ps1" in row.tags, "the tag is still recorded, it just is not the family"


def test_running_twice_updates_rather_than_duplicates(router, http, session_maker, settings, session):
    load_attack(router, http, session_maker, settings)
    load_iocs(router, http, session_maker, settings)
    before = len(session.scalars(select(Indicator)).all())

    router.add(MB_URL, abusech_fixture("malwarebazaar.csv"), headers={"ETag": '"mb-2"'})
    run_worker(MalwareBazaarWorker(), session_maker, http, settings)

    assert len(session.scalars(select(Indicator)).all()) == before


# --------------------------------------------------------------- the lookup
def test_lookup_finds_a_sha256(client_with_iocs):
    body = client_with_iocs.get("/api/iocs/lookup", params={"q": SHA256}).json()
    assert body["found"] is True and body["kind"] == "sha256" and body["total"] == 1


def test_lookup_is_case_insensitive(client_with_iocs):
    body = client_with_iocs.get("/api/iocs/lookup", params={"q": SHA256.upper()}).json()
    assert body["found"] is True


def test_lookup_finds_a_sample_by_its_md5(client_with_iocs):
    """The md5 is only in ``related``; one lookup has to answer for all three."""
    body = client_with_iocs.get("/api/iocs/lookup", params={"q": MD5}).json()
    assert body["found"] is True and body["kind"] == "md5"
    assert body["items"][0]["value"] == SHA256


def test_lookup_by_host_returns_every_url_on_it(client_with_iocs):
    body = client_with_iocs.get("/api/iocs/lookup", params={"q": "evil.example.test"}).json()
    assert body["found"] is True and body["total"] == 2


def test_a_miss_is_an_answer_and_says_what_was_searched(client_with_iocs):
    body = client_with_iocs.get("/api/iocs/lookup", params={"q": "b" * 64}).json()
    assert body["found"] is False and body["kind"] == "sha256" and body["items"] == []
    # Absence here is not evidence of safety, and the response has to say so.
    assert "MalwareBazaar" in body["scope"] and "URLhaus" in body["scope"]


def test_lookup_rejects_something_that_is_not_an_indicator(client_with_iocs):
    assert client_with_iocs.get("/api/iocs/lookup", params={"q": "not an indicator"}).status_code == 400


def test_lookup_rejects_a_query_that_is_too_short(client_with_iocs):
    assert client_with_iocs.get("/api/iocs/lookup", params={"q": "ab"}).status_code == 422


# -------------------------------------------------------------- the listing
def test_listing_rejects_an_unknown_kind(client_with_iocs):
    assert client_with_iocs.get("/api/iocs/indicators", params={"kind": "banana"}).status_code == 400


def test_listing_rejects_an_unknown_window(client_with_iocs):
    assert client_with_iocs.get("/api/iocs/indicators", params={"window": "banana"}).status_code == 400


def test_overview_counts_by_kind_and_source(client_with_iocs):
    body = client_with_iocs.get("/api/iocs/overview").json()
    assert body["by_kind"] == {"sha256": 3, "url": 3}
    assert body["by_source"] == {"malwarebazaar": 3, "urlhaus": 3}
    assert body["online"] == 2
