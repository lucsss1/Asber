"""Optional AI layer (Phase 3) — disabled by default.

Design contract, enforced by ``build_context`` below:

* The model is given ONLY text that this system collected, each fragment
  carrying its source URL and tier.
* Every generated statement must cite one of those fragments; anything that
  cannot be traced to a collected source is dropped by the caller.
* The UI labels the output "AI-generated summary" and renders the source links
  next to it.
* No AI call is ever made during ingestion, and none is made at all while
  ``AI_PROVIDER=none`` (the default).

Nothing here is wired into the API yet; it defines the seam so the feature can
be added without touching the ingestion or correlation code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

TASKS = {
    "threat_summary": "What happened?",
    "technical_summary": "How does the vulnerability work?",
    "attack_chain": "How could an attacker abuse this?",
    "detection_ideas": "What telemetry should a defender monitor?",
    "attack_mapping": "Which MITRE ATT&CK techniques are relevant?",
    "analyst_questions": "What should I investigate next?",
}

SYSTEM_PROMPT = """You are assisting a security analyst.
Use ONLY the numbered source fragments provided. Cite the fragment number for
every claim, like [3]. If the fragments do not support an answer, say so
explicitly. Never infer a threat actor, exploitation status or affected product
that is not stated in a fragment. Do not speculate."""


@dataclass
class Fragment:
    index: int
    text: str
    url: str
    source: str
    tier: int


@dataclass
class AiAnswer:
    task: str
    text: str
    fragments: list[Fragment]
    provider: str
    disclaimer: str = "AI-generated summary — verify each claim against the linked sources."


class AiProvider(Protocol):
    def complete(self, system: str, prompt: str) -> str: ...


def build_context(detail: dict, max_fragments: int = 20) -> list[Fragment]:
    """Turn a CVE detail payload into numbered, attributable fragments."""
    fragments: list[Fragment] = []

    def add(text: str | None, url: str, source: str, tier: int) -> None:
        if text and len(fragments) < max_fragments:
            fragments.append(Fragment(len(fragments) + 1, text.strip()[:1500], url, source, tier))

    cve = detail["cve_id"]
    overview = detail.get("overview") or {}
    add(overview.get("description"), f"https://nvd.nist.gov/vuln/detail/{cve}", "NVD", 1)
    kev = detail.get("kev") or {}
    if kev.get("in_kev"):
        add(f"CISA KEV: {kev.get('name')}. Required action: {kev.get('required_action')}. "
            f"Known ransomware use: {kev.get('ransomware_use')}.",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV", 1)
    for item in detail.get("exploitation", []):
        add(item.get("detail"), item.get("url") or "", item.get("source", ""), item.get("tier", 4))
    for doc in (detail.get("research", []) + detail.get("news", []))[:8]:
        add(f"{doc['title']}. {doc.get('summary') or ''}", doc["url"], doc["source"]["name"], doc["tier"])
    for tech in detail.get("attack", [])[:5]:
        add(f"ATT&CK {tech['external_id']} {tech['name']} ({tech['mapping']['method']} mapping): "
            f"{tech.get('description', '')}", tech.get("url") or "https://attack.mitre.org/", "MITRE ATT&CK", 1)
    return fragments


def build_prompt(task: str, detail: dict, fragments: list[Fragment]) -> str:
    if task not in TASKS:
        raise ValueError(f"unknown task {task!r}; expected one of {sorted(TASKS)}")
    lines = [f"Question: {TASKS[task]}", f"Subject: {detail['cve_id']}", "", "Source fragments:"]
    for f in fragments:
        lines.append(f"[{f.index}] ({f.source}, tier {f.tier}) {f.text}")
    lines += ["", "Answer in at most 8 sentences, citing fragment numbers."]
    return "\n".join(lines)


def is_enabled(provider_name: str) -> bool:
    return provider_name not in ("", "none", None)
