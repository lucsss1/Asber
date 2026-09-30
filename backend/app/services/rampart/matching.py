"""Does this CVE touch this asset, and how do we know?

Pure functions: no session, no network, no clock. Everything here takes plain
values and returns a verdict with its evidence, which is what makes the whole
matching layer testable from fixtures.

The governing rule is that **doubt resolves downwards**. ``affected`` is only
claimed when a version was parsed *and* compared successfully against a bound
we also parsed. Anything else — an absent range, a version we cannot order, a
CVE with no CPE at all — lands on ``possibly_affected``. Telling somebody they
are safe when we merely failed to read a version string is the one mistake this
module must never make; telling them to go and check is always survivable.

Version strings in the wild are worse than they look. Real values collected by
this system include ``10.0.25398.0``, ``0`` and ``Hh-B20211125.1046``, so the
comparator refuses anything it cannot read as an ordered sequence of integers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# What ``services.normalize`` writes into ``affected_products.versions`` for a
# CPE match. The format is ours, which is what makes parsing it back safe:
#   ">= 7.0.0 < 7.2.9"
_BOUND_RE = re.compile(r"(>=|<=|>|<)\s*([^\s<>=]+)")

_SPLIT_RE = re.compile(r"[.\-_+]")

AFFECTED = "affected"
POSSIBLY_AFFECTED = "possibly_affected"
NOT_AFFECTED = "not_affected"

IN = "in"
OUT = "out"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Bound:
    op: str
    version: str


@dataclass(frozen=True)
class Range:
    lower: Bound | None = None
    upper: Bound | None = None

    def __str__(self) -> str:
        parts = [f"{b.op} {b.version}" for b in (self.lower, self.upper) if b]
        return " ".join(parts)


@dataclass(frozen=True)
class MatchResult:
    state: str
    method: str
    confidence: str
    evidence: str


def normalise(value: str | None) -> str:
    """Fold a vendor or product name to the form used for comparison.

    NVD writes ``windows_server_2019`` where a CNA writes ``Windows Server
    2019``; both must land on the same key.
    """
    if not value:
        return ""
    return re.sub(r"[\s_]+", " ", value.strip().lower())


def parse_range(versions: str | None) -> Range | None:
    """Read back the bound string this project writes at ingest.

    Returns ``None`` for anything without an operator — a bare list like
    ``"10.0.25398.0"`` is a set of affected versions, not a range, and treating
    it as one would invent a boundary that no source stated.
    """
    if not versions:
        return None
    lower: Bound | None = None
    upper: Bound | None = None
    for op, version in _BOUND_RE.findall(versions):
        bound = Bound(op, version)
        if op in (">=", ">"):
            lower = bound
        else:
            upper = bound
    if lower is None and upper is None:
        return None
    return Range(lower, upper)


def cpe_version(cpe: str | None) -> str | None:
    """The version component of a CPE 2.3 string, when it is pinned.

    ``cpe:2.3:o:fortinet:fortios:7.2.8:*:...`` gives ``7.2.8``; a wildcard or
    ``-`` means the CPE says nothing about the version.
    """
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    version = parts[5].strip()
    return None if version in ("*", "-", "") else version


def _tokens(version: str) -> list[int] | None:
    """Split a version into integer components, or give up.

    Giving up is the point: a token this cannot read as an integer means the
    ordering is a guess, and a guess here produces a false ``not_affected``.
    """
    raw = [p for p in _SPLIT_RE.split(version.strip()) if p]
    if not raw:
        return None
    out: list[int] = []
    for part in raw:
        if not part.isdigit():
            return None
        out.append(int(part))
    return out


def compare_versions(a: str, b: str) -> int | None:
    """-1, 0, 1 — or ``None`` when the two cannot be ordered."""
    if a.strip() == b.strip():
        return 0
    ta, tb = _tokens(a), _tokens(b)
    if ta is None or tb is None:
        return None
    width = max(len(ta), len(tb))
    ta += [0] * (width - len(ta))
    tb += [0] * (width - len(tb))
    return (ta > tb) - (ta < tb)


def version_in_range(version: str | None, rng: Range | None) -> str:
    """``in`` / ``out`` / ``unknown`` for a version against a parsed range."""
    if not version or rng is None:
        return UNKNOWN
    for bound, inside in ((rng.lower, (0, 1)), (rng.upper, (-1, 0))):
        if bound is None:
            continue
        cmp = compare_versions(version, bound.version)
        if cmp is None:
            return UNKNOWN
        allowed = inside if bound.op in (">=", "<=") else tuple(c for c in inside if c != 0)
        if cmp not in allowed:
            return OUT
    return IN


def _same_product(asset, product) -> bool:
    a_vendor, a_product = normalise(asset.vendor), normalise(asset.product)
    p_vendor, p_product = normalise(product.vendor), normalise(product.product)
    if not a_product or not p_product:
        return False
    # The product carries the identity; a vendor recorded on only one side is
    # not evidence of a mismatch. "n/a" appears in collected data as a filler.
    if p_vendor in ("", "n/a") or a_vendor in ("", "n/a"):
        return a_product == p_product
    return a_vendor == p_vendor and a_product == p_product


def match_asset(asset, products, vuln=None) -> MatchResult | None:
    """Decide how one asset relates to one CVE.

    ``asset`` needs ``vendor``, ``product`` and ``version``; ``products`` are
    the CVE's ``affected_products`` rows; ``vuln`` is the CVE itself, used only
    for the KEV fallback. ``None`` means the two are unrelated — the asset's
    product is not among the CVE's affected products at all.
    """
    candidates = [p for p in products if _same_product(asset, p)]

    if not candidates:
        # A KEV entry whose product line matches but which carries no product
        # rows we can read. CISA named it exploited; that is worth surfacing.
        if vuln is not None and getattr(vuln, "in_kev", False) and _same_product(asset, vuln):
            return MatchResult(
                POSSIBLY_AFFECTED,
                "kev_fallback",
                "low",
                f"{asset.vendor} {asset.product} is named in the CISA KEV entry, "
                "which carries no machine-readable affected versions.",
            )
        return None

    label = f"{asset.vendor} {asset.product}".strip()
    if not asset.version:
        return MatchResult(
            POSSIBLY_AFFECTED,
            "vendor_product",
            "medium",
            f"{label} is listed as affected, but no version is recorded for this asset.",
        )

    out_of_range: list[str] = []
    undecided = False

    for product in candidates:
        pinned = cpe_version(product.cpe)
        if pinned is not None:
            cmp = compare_versions(asset.version, pinned)
            if cmp == 0:
                return MatchResult(
                    AFFECTED, "cpe_exact", "high",
                    f"{label} {asset.version} is the exact version named by {product.cpe}.",
                )
            if cmp is None:
                undecided = True
            else:
                out_of_range.append(f"{product.cpe} names {pinned}")
            continue

        rng = parse_range(product.versions)
        verdict = version_in_range(asset.version, rng)
        if verdict == IN:
            return MatchResult(
                AFFECTED, "cpe_version_range", "high",
                f"{label} {asset.version} falls inside the affected range {rng}"
                + (f" ({product.cpe})." if product.cpe else "."),
            )
        if verdict == OUT:
            out_of_range.append(f"{rng}")
        else:
            undecided = True

    if undecided or not out_of_range:
        return MatchResult(
            POSSIBLY_AFFECTED, "vendor_product", "medium",
            f"{label} is listed as affected, but version {asset.version} could not be "
            "compared against the published range.",
        )

    return MatchResult(
        NOT_AFFECTED, "cpe_version_range", "medium",
        f"{label} {asset.version} is outside every affected range ({'; '.join(out_of_range[:3])}).",
    )
