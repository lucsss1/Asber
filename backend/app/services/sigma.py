"""Sigma rule parsing — pure, no session, no I/O, nothing executed.

A detection rule is read as data and only ever as data. ``yaml.safe_load`` is
the only loader used here: ``yaml.load`` can construct arbitrary Python objects
and a rule corpus is third-party content. The detection body is normalised back
to YAML text and stored inert; it is never compiled, registered with an engine,
or run.

What makes the corpus worth ingesting is its tags. Measured on the
``sigma_all_rules`` archive of release r2026-07-01, 3,302 rules:

- 2,877 (87%) carry at least one ``attack.tXXXX`` tag
- 193 (5.8%) carry a ``cve.YYYY-NNNN`` tag, naming 140 distinct CVEs

Of those 140, 96 are in this corpus, and **all 96 are in CISA KEV and flagged
as actively exploited**. That is the shape of the feature: the ATT&CK mapping
carries the volume, and the CVE link is sparse but lands entirely on the part
of the corpus that matters most. Neither is inferred — both come from a tag the
rule author wrote, so both are ``explicit`` edges with the tag as evidence.
"""
from __future__ import annotations

import re

import yaml

#: ``attack.t1190`` and ``attack.t1059.001``; tactic tags (``attack.execution``)
#: deliberately do not match, since a tactic is not a technique.
_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t[0-9]{4}(?:\.[0-9]{3})?)$", re.IGNORECASE)

#: ``cve.2017-5638``. Only the hyphenated form occurs in the corpus; the dotted
#: form is accepted too rather than silently dropping a rule if upstream changes.
_CVE_TAG = re.compile(r"^cve\.([0-9]{4})[-.]([0-9]{4,})$", re.IGNORECASE)

#: Upstream's own vocabulary. Anything else is kept verbatim rather than
#: coerced, because a value we do not recognise is information, not an error.
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
LEVELS = ("informational", "low", "medium", "high", "critical")


class MalformedRule(ValueError):
    """The document is not a Sigma rule we can store."""


def techniques_from_tags(tags: list[str]) -> list[str]:
    """ATT&CK technique ids, uppercased, in first-seen order."""
    out: list[str] = []
    for tag in tags:
        m = _ATTACK_TECHNIQUE.match(str(tag).strip())
        if m:
            tid = m.group(1).upper()
            if tid not in out:
                out.append(tid)
    return out


def cves_from_tags(tags: list[str]) -> list[str]:
    """CVE ids named by ``cve.`` tags, normalised, in first-seen order."""
    out: list[str] = []
    for tag in tags:
        m = _CVE_TAG.match(str(tag).strip())
        if m:
            cve = f"CVE-{m.group(1)}-{m.group(2)}"
            if cve not in out:
                out.append(cve)
    return out


def _text(value, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text[:limit] or None


def _str_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [s for s in (_text(v, 500) for v in value) if s]


def parse_rule(text: str) -> dict:
    """One Sigma YAML document to a ``detection_rules`` row.

    Raises ``MalformedRule`` for anything that is not a usable rule — a rule
    without an id cannot be de-duplicated across releases, and one without a
    title cannot be shown. The caller counts those as malformed and carries on;
    a corpus of three thousand files will always contain a few.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise MalformedRule(f"unreadable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise MalformedRule("document is not a mapping")

    rule_id = _text(doc.get("id"), 300)
    if not rule_id:
        raise MalformedRule("rule has no id")
    title = _text(doc.get("title"), 500)
    if not title:
        raise MalformedRule(f"rule {rule_id} has no title")

    tags = _str_list(doc.get("tags"))
    logsource = doc.get("logsource")
    logsource = {k: _text(v, 300) for k, v in logsource.items()} if isinstance(logsource, dict) else {}

    detection = doc.get("detection")
    if detection is not None:
        # Normalised back to YAML rather than kept as the original slice: it
        # round-trips through safe_dump, so whatever is stored is known to be
        # plain data. It is text in a column, not a loaded rule.
        detection = yaml.safe_dump(detection, default_flow_style=False, sort_keys=False)

    status = _text(doc.get("status"), 32)
    level = _text(doc.get("level"), 32)
    return {
        "external_id": rule_id,
        "title": title,
        "description": _text(doc.get("description"), 2000),
        "rule_format": "sigma",
        "status": status.lower() if status else None,
        "level": level.lower() if level else None,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": _str_list(doc.get("falsepositives")),
        "references": _str_list(doc.get("references")),
        "tags": tags,
        "techniques": techniques_from_tags(tags),
        "cve_ids": cves_from_tags(tags),
        "author": _text(doc.get("author"), 300),
    }
