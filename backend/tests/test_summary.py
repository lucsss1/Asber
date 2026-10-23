"""The Overview's executive figures.

The shapes here were chosen after measuring the data, and these tests pin the
decisions that measurement produced — most importantly that the two totals on
screen are allowed to differ and are each correct for what they count.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.summary import SEVERITY_ORDER


@pytest.fixture
def client_env(router, http, session_maker, settings, monkeypatch):
    from tests.test_correlation import full_pipeline

    monkeypatch.setattr("app.config.get_settings", lambda: settings, raising=False)
    full_pipeline(router, http, session_maker, settings)
    with TestClient(app) as c:
        c.post("/api/rampart/assets", json={
            "label": "Edge firewall", "category": "firewall",
            "vendor": "fortinet", "product": "fortios", "version": "7.0.13",
        })
        yield c


def test_severity_always_reports_every_class_even_at_zero(client_env):
    """A missing class is not the same as a zero one.

    If the API only returned the classes that occurred, a column would vanish
    from the chart rather than stand at zero, and the reader would have no way
    to tell "none are critical" from "critical was not measured".
    """
    body = client_env.get("/api/summary/environment").json()
    assert [s["severity"] for s in body["severity"]] == list(SEVERITY_ORDER)


def test_unscored_is_its_own_class_not_folded_into_low(client_env):
    body = client_env.get("/api/summary/environment").json()
    classes = {s["severity"] for s in body["severity"]}
    assert "UNSCORED" in classes, "'we do not know how bad' is not 'it is not bad'"


def test_the_verdict_total_exceeds_reaching_by_the_ruled_out(client_env):
    """The donut and the figures carry different totals, on purpose.

    The donut divides everything matched, including what was ruled out; the
    figures count only what reaches you. They differ by exactly the ruled-out
    slice, and the page labels the donut 'matched' so the difference is
    readable rather than looking like an error.
    """
    body = client_env.get("/api/summary/environment").json()
    verdict_total = sum(v["count"] for v in body["verdict"])
    ruled_out = next(v["count"] for v in body["verdict"] if v["state"] == "not_affected")
    assert verdict_total - ruled_out == body["reaching"]
    assert body["figures"]["total"] == body["reaching"]


def test_verdict_keeps_its_three_states_in_reading_order(client_env):
    body = client_env.get("/api/summary/environment").json()
    assert [v["state"] for v in body["verdict"]] == [
        "affected", "possibly_affected", "not_affected"]


def test_figures_never_exceed_their_denominator(client_env):
    body = client_env.get("/api/summary/environment").json()
    f = body["figures"]
    for key in ("in_kev", "has_public_exploit", "has_detection_rule"):
        assert f[key] <= f["total"], f"{key} counts more than the set it is drawn from"


def test_corpus_summary_works_without_an_environment(client_env):
    """The charts must not be empty on a first run that simply has no inventory."""
    body = client_env.get("/api/summary/corpus").json()
    assert [s["severity"] for s in body["severity"]] == list(SEVERITY_ORDER)
    assert body["total"] >= 1
