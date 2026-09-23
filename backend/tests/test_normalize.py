"""Parsing / normalisation of external payloads, including malformed data."""
from __future__ import annotations

import pytest

from app.services.normalize import MalformedRecord, parse_kev_entry, parse_nvd_cve, valid_cve_id
from app.services.sanitize import html_to_text, parse_dt, safe_url
from tests.conftest import fixture_json


def test_kev_entry_normalised():
    data = fixture_json("cisa_kev.json")["vulnerabilities"][0]
    kev = parse_kev_entry(data)
    assert kev["cve_id"] == "CVE-2026-11111"
    assert kev["vendor"] == "Fortinet"
    assert kev["kev_date_added"].isoformat() == "2026-09-10"
    assert kev["kev_ransomware"] == "Known"
    assert kev["cwes"] == ["CWE-288"]
    # NVD links are dropped from notes; the vendor advisory is kept
    assert "https://fortiguard.fortinet.com/psirt/FG-IR-26-001" in kev["note_urls"]


def test_kev_malformed_row_rejected():
    bad = fixture_json("cisa_kev.json")["vulnerabilities"][2]
    with pytest.raises(MalformedRecord):
        parse_kev_entry(bad)


@pytest.mark.parametrize("value", ["CVE-2026-1", "cve-abc", None, 42, {"id": "x"}, "CVE-20260-1111"])
def test_invalid_cve_ids_rejected(value):
    with pytest.raises(MalformedRecord):
        valid_cve_id(value)


def test_nvd_cve_normalised():
    cve = fixture_json("nvd_cves.json")["vulnerabilities"][0]["cve"]
    out = parse_nvd_cve(cve)
    assert out["cvss_score"] == 9.8 and out["cvss_severity"] == "CRITICAL" and out["cvss_version"] == "3.1"
    assert out["ssvc_exploitation"] == "active" and out["ssvc_technical_impact"] == "total"
    assert out["cwes"] == ["CWE-288", "CWE-94"]
    assert out["description"].startswith("An authentication bypass")
    # CPE + CNA "affected" merged, vendor/product derived from the CPE
    vendors = {p["vendor"] for p in out["products"]}
    assert "fortinet" in vendors and "Fortinet" in vendors
    versions = [p["versions"] for p in out["products"] if p["cpe"].endswith("fortios:*:*:*:*:*:*:*:*")]
    assert versions and ">= 7.0.0" in versions[0] and "< 7.0.14" in versions[0]
    # reference classification + javascript: URL dropped
    kinds = {r["url"]: r["ref_type"] for r in out["references"]}
    assert kinds["https://fortiguard.fortinet.com/psirt/FG-IR-26-001"] == "vendor_advisory"
    assert kinds["https://www.exploit-db.com/exploits/52001"] == "exploit"
    assert not any("javascript" in u for u in kinds)


def test_nvd_missing_metrics_is_not_fatal():
    cve = fixture_json("nvd_cves.json")["vulnerabilities"][1]["cve"]
    out = parse_nvd_cve(cve)
    assert out["cve_id"] == "CVE-2026-33333"
    assert out["cvss_score"] is None and out["products"] == [] and out["references"] == []


@pytest.mark.parametrize("payload", [None, [], "string", {"id": "nope"}])
def test_nvd_malformed_payloads(payload):
    with pytest.raises(MalformedRecord):
        parse_nvd_cve(payload)


def test_html_is_reduced_to_text():
    dirty = '<p>Hello <b>world</b></p><script>alert("xss")</script><img src=x onerror=alert(1)>'
    text = html_to_text(dirty)
    assert "alert" not in text and "<" not in text
    assert text == "Hello world"


def test_html_to_text_truncates():
    assert html_to_text("word " * 200, 50).endswith("…")


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html;base64,AAA", "file:///etc/passwd",
                                 "ftp://x/y", "", None, "https://exa mple.com", "http://host\n/x"])
def test_unsafe_urls_rejected(bad):
    assert safe_url(bad) is None


def test_tracking_parameters_removed():
    assert safe_url("https://ex.com/a?utm_source=rss&id=7") == "https://ex.com/a?id=7"


def test_parse_dt_handles_junk():
    assert parse_dt("not a date") is None
    assert parse_dt("2026-09-10").isoformat().startswith("2026-09-10T00:00:00+00:00")


def test_cvss_prefers_nvd_over_cna_when_neither_is_primary():
    """Regression: CVE-2020-1472 ships two Secondary v3.1 metrics — Microsoft's 5.5
    and NVD's 10.0. Taking the first entry reported the vulnerability as MEDIUM."""
    cve = {
        "id": "CVE-2020-1472",
        "descriptions": [{"lang": "en", "value": "Netlogon elevation of privilege."}],
        "metrics": {
            "cvssMetricV31": [
                {"source": "secure@microsoft.com", "type": "Secondary",
                 "cvssData": {"version": "3.1", "baseScore": 5.5, "baseSeverity": "MEDIUM",
                              "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"}},
                {"source": "nvd@nist.gov", "type": "Secondary",
                 "cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL",
                              "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
            ],
            "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                              "cvssData": {"version": "2.0", "baseScore": 9.3}}],
        },
    }
    out = parse_nvd_cve(cve)
    assert out["cvss_score"] == 10.0 and out["cvss_severity"] == "CRITICAL"


def test_cvss_falls_back_to_primary_then_first():
    base = {"id": "CVE-2026-1000", "descriptions": [{"lang": "en", "value": "x"}]}
    primary = parse_nvd_cve({**base, "metrics": {"cvssMetricV31": [
        {"source": "cna@example.com", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 4.0}},
        {"source": "other@example.com", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.0}},
    ]}})
    assert primary["cvss_score"] == 7.0
    only_cna = parse_nvd_cve({**base, "metrics": {"cvssMetricV31": [
        {"source": "cna@example.com", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 4.0}},
    ]}})
    assert only_cna["cvss_score"] == 4.0


def test_managed_platform_database_url_gets_the_right_driver():
    """Render/Heroku-style URLs name no driver; SQLAlchemy would pick psycopg2,
    which this project does not install."""
    from app.config import Settings

    for raw in ("postgres://u:p@host:5432/db", "postgresql://u:p@host:5432/db"):
        assert Settings(database_url=raw).database_url == "postgresql+psycopg://u:p@host:5432/db"
    # an explicit driver is left alone
    explicit = "postgresql+psycopg://u:p@host/db"
    assert Settings(database_url=explicit).database_url == explicit
    assert Settings(database_url="sqlite://").database_url == "sqlite://"
