"""Threat Relevance Score (0–100).

This is an internal *prioritisation* score. It is NOT a replacement for CVSS
and every point it awards is returned as an explicit, human-readable reason.
Weights live in one table so they are easy to audit and tune.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone

WEIGHTS = {
    "kev": 25,
    "active_exploitation": 15,
    "ransomware": 10,
    "public_exploit": 12,
    "public_poc": 8,
    "threat_actor": 8,
    "rce": 8,
    "auth_bypass": 7,
    "privilege_escalation": 5,
    "internet_facing": 6,
    "cvss_max": 10,  # scaled: cvss/10 * cvss_max
    "sources_per_extra": 3,
    "sources_max": 9,
    "recent_7d": 8,
    "recent_30d": 4,
    "products_5": 3,
    "products_20": 5,
}


@dataclass
class ScoreInput:
    in_kev: bool = False
    active_exploitation_evidence: list[str] = field(default_factory=list)
    ransomware: bool = False
    exploit_count: int = 0
    poc_count: int = 0
    ssvc_poc: bool = False  # CISA SSVC "exploitation: poc" (via NVD)
    threat_actors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    internet_facing: bool = False
    cvss_score: float | None = None
    independent_sources: int = 0
    most_recent_signal: datetime | date | None = None
    affected_product_count: int = 0


@dataclass
class ScoreResult:
    score: int
    reasons: list[dict]


def compute_relevance(inp: ScoreInput, now: datetime | None = None) -> ScoreResult:
    now = now or datetime.now(timezone.utc)
    reasons: list[dict] = []

    def add(factor: str, points: float, detail: str) -> None:
        if points > 0:
            reasons.append({"factor": factor, "points": round(points, 1), "detail": detail})

    if inp.in_kev:
        add("CISA KEV", WEIGHTS["kev"], "Listed in the CISA Known Exploited Vulnerabilities catalog")
    if inp.active_exploitation_evidence:
        add("Active exploitation", WEIGHTS["active_exploitation"],
            "Exploitation reported by: " + ", ".join(sorted(set(inp.active_exploitation_evidence))[:5]))
    if inp.ransomware:
        add("Ransomware association", WEIGHTS["ransomware"], "Known or reported use in ransomware campaigns")
    if inp.exploit_count:
        add("Public exploit", WEIGHTS["public_exploit"], f"{inp.exploit_count} public exploit(s) (e.g. Exploit-DB)")
    if inp.poc_count or inp.ssvc_poc:
        parts = []
        if inp.poc_count:
            parts.append(f"{inp.poc_count} public PoC repo(s) (unverified)")
        if inp.ssvc_poc:
            parts.append("CISA SSVC reports public PoC")
        add("Public PoC", WEIGHTS["public_poc"], "; ".join(parts))
    if inp.threat_actors:
        add("Threat actor association", WEIGHTS["threat_actor"],
            "Mentioned alongside: " + ", ".join(sorted(set(inp.threat_actors))[:5]))
    if "rce" in inp.tags:
        add("Remote code execution", WEIGHTS["rce"], "Impact classified as RCE (description/CWE)")
    if "auth_bypass" in inp.tags:
        add("Authentication bypass", WEIGHTS["auth_bypass"], "Impact classified as authentication bypass")
    if "privilege_escalation" in inp.tags:
        add("Privilege escalation", WEIGHTS["privilege_escalation"], "Impact classified as privilege escalation")
    if inp.internet_facing:
        add("Internet-facing product", WEIGHTS["internet_facing"], "Affected product is typically Internet-exposed")
    if inp.cvss_score:
        add("CVSS severity", inp.cvss_score / 10 * WEIGHTS["cvss_max"], f"CVSS base score {inp.cvss_score}")
    if inp.independent_sources > 1:
        pts = min(WEIGHTS["sources_max"], (inp.independent_sources - 1) * WEIGHTS["sources_per_extra"])
        add("Multiple independent sources", pts, f"{inp.independent_sources} independent sources")
    if inp.most_recent_signal:
        sig = inp.most_recent_signal
        if not isinstance(sig, datetime):
            sig = datetime(sig.year, sig.month, sig.day, tzinfo=timezone.utc)
        elif sig.tzinfo is None:
            sig = sig.replace(tzinfo=timezone.utc)
        age = (now - sig).days
        if age <= 7:
            add("Recency", WEIGHTS["recent_7d"], f"New activity {max(age, 0)} day(s) ago")
        elif age <= 30:
            add("Recency", WEIGHTS["recent_30d"], f"New activity {age} days ago")
    if inp.affected_product_count >= 20:
        add("Broad impact", WEIGHTS["products_20"], f"{inp.affected_product_count} affected product entries")
    elif inp.affected_product_count >= 5:
        add("Broad impact", WEIGHTS["products_5"], f"{inp.affected_product_count} affected product entries")

    reasons.sort(key=lambda r: -r["points"])
    total = int(round(min(100.0, sum(r["points"] for r in reasons))))
    return ScoreResult(score=total, reasons=reasons)
