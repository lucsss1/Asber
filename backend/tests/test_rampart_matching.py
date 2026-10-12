"""The matching layer, exercised on the shapes real collected data actually has.

Every value in ``versions`` below was taken from the live database rather than
invented, because the failure mode this module has to survive is not a clean
range — it is ``Hh-B20211125.1046``.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.rampart.matching import (
    AFFECTED,
    IN,
    NOT_AFFECTED,
    OUT,
    POSSIBLY_AFFECTED,
    UNKNOWN,
    compare_versions,
    cpe_version,
    match_asset,
    normalise,
    parse_range,
    version_in_range,
    version_sort_key,
    version_tokens,
)


def asset(vendor="fortinet", product="fortios", version="7.2.8"):
    return SimpleNamespace(vendor=vendor, product=product, version=version)


def product(vendor="fortinet", name="fortios", cpe="", versions=None):
    return SimpleNamespace(vendor=vendor, product=name, cpe=cpe, versions=versions)


# --------------------------------------------------------------------- parse
@pytest.mark.parametrize(
    "raw, lower, upper",
    [
        (">= 7.0.0 < 7.2.9", ("7.0.0", ">="), ("7.2.9", "<")),
        ("< 10.0.17763.9245", None, ("10.0.17763.9245", "<")),
        ("> 1.0 <= 2.0", ("1.0", ">"), ("2.0", "<=")),
    ],
)
def test_parse_range_reads_our_own_format(raw, lower, upper):
    rng = parse_range(raw)
    assert (rng.lower.version, rng.lower.op) == lower if lower else rng.lower is None
    assert (rng.upper.version, rng.upper.op) == upper if upper else rng.upper is None


@pytest.mark.parametrize("raw", [None, "", "10.0.25398.0", "0", "Hh-B20211125.1046", "n/a"])
def test_a_bare_version_list_is_not_a_range(raw):
    """A list of affected versions states no boundary; inventing one would be a lie."""
    assert parse_range(raw) is None


# ----------------------------------------------------------------------- cpe
@pytest.mark.parametrize(
    "cpe, expected",
    [
        ("cpe:2.3:o:fortinet:fortios:7.2.8:*:*:*:*:*:*:*", "7.2.8"),
        ("cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*", None),
        ("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*", None),
        ("", None),
        (None, None),
        ("not-a-cpe", None),
    ],
)
def test_cpe_version_only_when_pinned(cpe, expected):
    assert cpe_version(cpe) == expected


# ------------------------------------------------------------------ ordering
@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("7.2.8", "7.2.9", -1),
        ("7.2.9", "7.2.8", 1),
        ("7.2", "7.2.0", 0),
        ("10.0.17763.9245", "10.0.17763.9000", 1),
        ("1.0.0", "1.0.0", 0),
    ],
)
def test_numeric_versions_order(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize(
    "a, b",
    [("Hh-B20211125.1046", "1.0"), ("7.2.8b", "7.2.9"), ("1.0.0-rc1", "1.0.0"), ("", "1.0")],
)
def test_unreadable_versions_refuse_to_order(a, b):
    """Refusing is the safe answer: a guess here produces a false not_affected."""
    assert compare_versions(a, b) is None


def test_identical_unreadable_strings_are_still_equal():
    assert compare_versions("Hh-B20211125.1046", "Hh-B20211125.1046") == 0


# --------------------------------------------------------------------- range
@pytest.mark.parametrize(
    "version, raw, expected",
    [
        ("7.2.8", ">= 7.0.0 < 7.2.9", IN),
        ("7.2.9", ">= 7.0.0 < 7.2.9", OUT),          # exclusive upper bound
        ("7.2.9", ">= 7.0.0 <= 7.2.9", IN),          # inclusive upper bound
        ("7.0.0", ">= 7.0.0 < 7.2.9", IN),           # inclusive lower bound
        ("7.0.0", "> 7.0.0 < 7.2.9", OUT),           # exclusive lower bound
        ("6.9.9", ">= 7.0.0 < 7.2.9", OUT),
        ("7.2.8", None, UNKNOWN),
        (None, ">= 7.0.0 < 7.2.9", UNKNOWN),
        ("Hh-B20211125.1046", ">= 7.0.0 < 7.2.9", UNKNOWN),
    ],
)
def test_boundaries_are_respected(version, raw, expected):
    assert version_in_range(version, parse_range(raw)) == expected


# --------------------------------------------------------------------- match
def test_unrelated_product_is_no_match():
    assert match_asset(asset(), [product(vendor="microsoft", name="windows 10")]) is None


def test_version_inside_the_range_is_affected():
    result = match_asset(asset(version="7.2.8"), [product(versions=">= 7.0.0 < 7.2.9")])
    assert result.state == AFFECTED
    assert result.method == "cpe_version_range"
    assert "7.2.8" in result.evidence and ">= 7.0.0 < 7.2.9" in result.evidence


def test_pinned_cpe_matching_exactly_is_affected():
    result = match_asset(asset(version="7.2.8"),
                         [product(cpe="cpe:2.3:o:fortinet:fortios:7.2.8:*:*:*:*:*:*:*")])
    assert result.state == AFFECTED
    assert result.method == "cpe_exact"


def test_version_outside_every_range_is_not_affected_and_is_kept():
    result = match_asset(asset(version="8.0.0"), [product(versions=">= 7.0.0 < 7.2.9")])
    assert result.state == NOT_AFFECTED
    assert "outside" in result.evidence


def test_no_version_on_the_asset_is_possibly_affected():
    result = match_asset(asset(version=None), [product(versions=">= 7.0.0 < 7.2.9")])
    assert result.state == POSSIBLY_AFFECTED
    assert result.method == "vendor_product"


def test_cve_without_any_range_is_possibly_affected():
    """More than a third of collected rows carry no usable version at all."""
    result = match_asset(asset(), [product(versions="10.0.25398.0")])
    assert result.state == POSSIBLY_AFFECTED


def test_unreadable_version_never_claims_not_affected():
    """The whole point: an unparseable version must not read as safe."""
    result = match_asset(asset(version="Hh-B20211125.1046"), [product(versions=">= 7.0.0 < 7.2.9")])
    assert result.state == POSSIBLY_AFFECTED


def test_one_range_matching_wins_over_another_that_does_not():
    result = match_asset(
        asset(version="7.2.8"),
        [product(versions=">= 6.0.0 < 6.4.0"), product(versions=">= 7.0.0 < 7.2.9")],
    )
    assert result.state == AFFECTED


def test_kev_entry_without_product_rows_still_surfaces():
    vuln = SimpleNamespace(vendor="fortinet", product="fortios", in_kev=True)
    result = match_asset(asset(), [], vuln)
    assert result.state == POSSIBLY_AFFECTED
    assert result.method == "kev_fallback"


def test_non_kev_cve_without_product_rows_is_no_match():
    vuln = SimpleNamespace(vendor="fortinet", product="fortios", in_kev=False)
    assert match_asset(asset(), [], vuln) is None


# ----------------------------------------------------------------- normalise
@pytest.mark.parametrize(
    "a, b",
    [("windows_server_2019", "Windows Server 2019"), ("FortiOS", "fortios"), ("  nginx ", "nginx")],
)
def test_vendor_vocabularies_fold_together(a, b):
    assert normalise(a) == normalise(b)


def test_filler_vendor_does_not_block_a_product_match():
    """Collected rows carry vendor "n/a"; the product still identifies the thing."""
    result = match_asset(asset(vendor="fortinet", product="fortios", version="7.2.8"),
                         [product(vendor="n/a", name="fortios", versions=">= 7.0.0 < 7.2.9")])
    assert result is not None and result.state == AFFECTED


# --------------------------------------------------------- version suggestions
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("7.4.0, 7.2.0, 7.0.0, 6.4.0", ["7.4.0", "7.2.0", "7.0.0", "6.4.0"]),
        ("< 10.0.26100.2314", ["10.0.26100.2314"]),
        (">= 7.0.0 < 7.2.9", ["7.0.0", "7.2.9"]),   # the two-bound form is the common one
        ("10.0.26100.0", ["10.0.26100.0"]),
    ],
)
def test_version_tokens_reads_every_shape_the_column_holds(raw, expected):
    assert version_tokens(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "(Server Core installation)", "Hh-B20211125.1046", "0", "n/a"])
def test_version_tokens_refuses_what_is_not_a_version(raw):
    """The same column carries build labels, prose and junk."""
    assert version_tokens(raw) == []


def test_versions_sort_numerically_not_lexically():
    """Lexical order puts .33158 before .3981, which is wrong by three orders."""
    got = sorted(["10.0.26100.3981", "10.0.26100.33158", "10.0.26100.2314"],
                 key=version_sort_key, reverse=True)
    assert got == ["10.0.26100.33158", "10.0.26100.3981", "10.0.26100.2314"]
