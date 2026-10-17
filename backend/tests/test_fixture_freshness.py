"""The fixtures must not rot with the calendar.

Three tests have now gone red on a date change rather than a code change, each
found with the suite already broken and each diagnosed from scratch:

- 2026-10-10 — ``cisa_kev.json``: the older of two valid entries aged out of
  the 30-day window, and ``test_dashboard_overview`` lost its ``kev_added``.
- 2026-10-15 — ``feed_research.xml``: the APT28 item, the only one carrying an
  ATT&CK technique mention, aged out and ``trending_attack`` came back empty.
- 2026-10-16 — ``exploitdb.csv``: the 2026-09-11 row crossed the boundary and
  ``new_exploits`` went to zero.

Curing them one at a time guarantees a fourth. This closes the class: any date
sitting in a fixture that the dashboard's windowed queries read has to be
anchored to today through a helper in ``conftest``, and a fixture that grows a
fixed recent date fails here, loudly, naming the file — instead of surfacing
weeks later as an assertion nobody can explain.

Deliberately old and deliberately malformed values are exempt by name. They
exist to be skipped, and being skipped is what they test.
"""
from __future__ import annotations

import pathlib
import re
from datetime import datetime, timedelta, timezone

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

#: An ISO date (2026-09-11) or an RFC 822 one (Mon, 14 Sep 2026).
_ISO = re.compile(r"\b(20[0-9]{2})-([0-9]{2})-([0-9]{2})\b")
_RFC822 = re.compile(r"\b([0-9]{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (20[0-9]{2})\b")
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

#: The widest window the dashboard offers. A date inside it is load-bearing;
#: one outside it cannot drift across a boundary that matters.
WINDOW_DAYS = 90

#: Dates that are supposed to be old, or that exist to break a parser.
EXEMPT = {
    "1999-01-01",   # cisa_kev.json / exploitdb.csv: the "too old to count" row
    "2026-01-01",   # exploitdb.csv: attached to the malformed-id row
    "not-a-date",   # cisa_kev.json: the deliberately malformed dateAdded
}

#: Fixtures whose dates are read through an anchoring helper in conftest, so
#: whatever is written in the file is overwritten before a worker sees it.
ANCHORED = {
    "cisa_kev.json": "kev_fixture()",
    "feed_research.xml": "research_fixture()",
    "exploitdb.csv": "exploitdb_fixture()",
}


def _dates(text: str) -> set[str]:
    found = {f"{y}-{m}-{d}" for y, m, d in _ISO.findall(text)}
    for day, mon, year in _RFC822.findall(text):
        found.add(f"{year}-{_MONTHS[mon]:02d}-{int(day):02d}")
    return found


@pytest.mark.parametrize("path", sorted(p for p in FIXTURES.iterdir() if p.is_file()),
                         ids=lambda p: p.name)
def test_no_fixture_carries_an_unanchored_recent_date(path: pathlib.Path):
    """A recent fixed date in a fixture is a test that expires.

    If this fails on a file already in ``ANCHORED``, the helper has stopped
    covering one of its dates. If it fails on a new file, either anchor it the
    same way or add the value to ``EXEMPT`` with a reason.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        pytest.skip(f"{path.name} is not text")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).date()
    recent = sorted(d for d in _dates(text) - EXEMPT
                    if datetime.strptime(d, "%Y-%m-%d").date() >= cutoff)
    if not recent:
        return

    helper = ANCHORED.get(path.name)
    assert helper, (
        f"{path.name} carries recent fixed date(s) {recent} and nothing anchors them. "
        f"Any assertion that depends on them will go red on a date change, not a code "
        f"change. Add an anchoring helper to conftest (see kev_fixture) and register it "
        f"in ANCHORED, or add the value to EXEMPT with a reason."
    )


def test_every_anchored_fixture_still_exists():
    """A rename must not silently drop a file out of the check above."""
    missing = [name for name in ANCHORED if not (FIXTURES / name).exists()]
    assert not missing, f"ANCHORED names fixtures that no longer exist: {missing}"


@pytest.mark.parametrize("helper", sorted(ANCHORED.values()))
def test_every_anchoring_helper_is_actually_wired_up(helper: str):
    """A helper nobody calls is a helper that stopped working.

    ``research_fixture`` existed for a day before anything used it, which is
    exactly long enough for the thing it fixes to come back.
    """
    name = helper.rstrip("()")
    used = [p.name for p in pathlib.Path(__file__).parent.glob("test_*.py")
            if f"{name}(" in p.read_text(encoding="utf-8") and p.name != pathlib.Path(__file__).name]
    assert used, f"{helper} is defined in conftest but no test calls it"
