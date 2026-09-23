"""Failure backoff: a source that keeps failing must not be retried on its
normal schedule, or an outage at the other end becomes a tight retry loop."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.ingestion.base import BACKOFF_CAP_SECONDS, backoff_seconds, due_for_run, run_worker
from app.models import Source
from app.workers.cisa_kev import CisaKevWorker
from tests.test_workers import KEV_URL

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


def source(failures: int, interval: int = 900, last_attempt: datetime | None = NOW) -> Source:
    return Source(key="s", name="s", homepage="", endpoint="", category="c", source_type="t", tier=1,
                  method="json", interval_seconds=interval, consecutive_failures=failures,
                  last_attempt=last_attempt, state={})


def test_healthy_source_has_no_backoff():
    assert backoff_seconds(source(0)) == 0
    assert due_for_run(source(0), NOW) is True


@pytest.mark.parametrize("failures,expected", [(1, 1800), (2, 3600), (3, 7200), (4, 14400)])
def test_backoff_doubles_with_each_failure(failures, expected):
    assert backoff_seconds(source(failures)) == expected


def test_backoff_is_capped():
    assert backoff_seconds(source(50)) == BACKOFF_CAP_SECONDS
    # even a slow source cannot exceed the cap
    assert backoff_seconds(source(50, interval=6 * 3600)) == BACKOFF_CAP_SECONDS


def test_failing_source_is_skipped_until_its_window_passes():
    s = source(3)  # 2 h backoff
    assert due_for_run(s, NOW + timedelta(minutes=30)) is False
    assert due_for_run(s, NOW + timedelta(hours=1, minutes=59)) is False
    assert due_for_run(s, NOW + timedelta(hours=2, seconds=1)) is True


def test_source_never_attempted_is_always_due():
    assert due_for_run(source(5, last_attempt=None), NOW) is True


def test_failures_accumulate_then_reset_on_success(router, http, session_maker, settings, session):
    """The counter that drives the backoff is maintained by the worker runner."""
    router.add(KEV_URL, b"upstream down", status=500)
    run_worker(CisaKevWorker(), session_maker, http, settings)
    run_worker(CisaKevWorker(), session_maker, http, settings)
    row = session.scalar(select(Source).where(Source.key == "cisa_kev"))
    session.refresh(row)
    assert row.consecutive_failures == 2
    assert backoff_seconds(row) > row.interval_seconds  # next attempt is delayed

    from tests.conftest import fixture

    router.add(KEV_URL, fixture("cisa_kev.json"))
    run_worker(CisaKevWorker(), session_maker, http, settings)
    session.refresh(row)
    assert row.consecutive_failures == 0
    assert due_for_run(row, NOW) is True  # recovery clears the backoff immediately
