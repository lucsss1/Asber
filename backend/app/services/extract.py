"""Entity extraction from free text (titles, summaries, feed content).

Deterministic and explainable: regexes for identifiers, a dictionary built from
the local MITRE ATT&CK copy for group / software / campaign names, and keyword
tables for impact / platform classification. No ML, nothing invented.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AttackObject

CVE_RE = re.compile(r"\bCVE[-‐‑–](\d{4})[-‐‑–](\d{4,7})\b", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b")
EDB_RE = re.compile(r"\bEDB[-\s]?(?:ID[:\s]*)?(\d{3,6})\b", re.IGNORECASE)

EXPLOITATION_PHRASES = re.compile(
    r"actively exploit(?:ed|ing)|under active exploitation|in-the-wild exploitation|"
    # "exploiting CVE-… in the wild", "exploited … in the wild"
    r"exploit(?:s|ed|ing|ation)[^.\n]{0,60}?in the wild|"
    r"exploitation (?:has been|was) (?:detected|observed)|zero-day|0-day|exploited as a zero|"
    r"known to be exploited|attacks exploiting|(?:hackers|attackers|adversaries) (?:are )?exploit|"
    r"exploit(?:ed|ing|s) (?:the )?(?:flaw|bug|vulnerabilit|CVE-)",
    re.IGNORECASE,
)
RANSOMWARE_RE = re.compile(r"\bransomware\b", re.IGNORECASE)

# Names matched only with their exact ATT&CK capitalisation (common words,
# short names, or families whose names often appear in unrelated prose).
CASE_SENSITIVE_NAMES = {
    "at", "net", "ping", "tor", "reg", "cmd", "expand", "page", "ftp", "arp", "route", "tasklist", "systeminfo",
    "whoami", "schtasks", "netsh", "esentutl", "ifconfig", "xcopy", "certutil", "wevtutil", "nltest",
    "empire", "komplex", "machete", "carbon", "turla", "rover", "prism", "ebury", "lucifer", "zox", "hydraq",
    "flame", "duqu", "regin", "kasidet", "sykipot", "mis-type", "misdat", "mosquito", "dust storm",
    "operation wocao", "cardinal rat", "bonadan", "sunburst", "raindrop", "doki", "p.a.s. webshell", "cuba",
    "royal", "play", "akira", "black basta", "hive", "conti", "lockbit", "maze", "ryuk", "egregor",
    "gold", "silver", "sibot", "goopy", "gazer", "orz", "remexi", "sword", "unknown", "matryoshka", "kinsing",
    "action rat", "agent tesla", "bumblebee", "ursnif", "emotet", "trickbot", "qakbot",
}
# Names never matched at all (too generic even with exact capitalisation).
NEVER_MATCH = {"at", "net", "ping", "tor", "reg", "cmd", "expand", "page", "ftp", "arp", "route", "unknown",
               "gold", "silver", "play", "royal", "sword", "carbon", "prism", "flame", "rover", "hive", "maze",
               "cuba", "doki", "orz", "zox"}

IMPACT_KEYWORDS = {
    "rce": re.compile(r"remote code execution|arbitrary code execution|execute arbitrary (?:code|commands)|"
                      r"code injection|command injection|\bRCE\b|deserializ", re.I),
    "privilege_escalation": re.compile(r"privilege escalation|elevation of privilege|escalate privileges|"
                                       r"gain (?:root|system|elevated) privileges|\bEoP\b|\bLPE\b", re.I),
    "auth_bypass": re.compile(r"authentication bypass|bypass (?:the )?authentication|missing authentication|"
                              r"unauthenticated (?:attacker|access)|improper authentication|auth bypass", re.I),
    "sqli": re.compile(r"sql injection", re.I),
    "path_traversal": re.compile(r"path traversal|directory traversal", re.I),
    "info_disclosure": re.compile(r"information disclosure|sensitive information", re.I),
    "dos": re.compile(r"denial[- ]of[- ]service", re.I),
    "memory_corruption": re.compile(r"use[- ]after[- ]free|buffer overflow|out-of-bounds write|heap overflow|"
                                    r"type confusion|memory corruption", re.I),
}
CWE_IMPACT = {
    "rce": {"CWE-94", "CWE-77", "CWE-78", "CWE-502", "CWE-95", "CWE-917", "CWE-1336", "CWE-434"},
    "privilege_escalation": {"CWE-269", "CWE-250", "CWE-266", "CWE-274", "CWE-648"},
    "auth_bypass": {"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-302", "CWE-1390", "CWE-798"},
    "sqli": {"CWE-89"},
    "path_traversal": {"CWE-22", "CWE-23", "CWE-35"},
    "memory_corruption": {"CWE-416", "CWE-787", "CWE-119", "CWE-120", "CWE-122", "CWE-843"},
}

PLATFORM_KEYWORDS = {
    "windows": re.compile(r"\bwindows\b|win32k|\bntlm\b|smbv?\d?\b|\blsass\b|\bmicrosoft\b", re.I),
    "linux": re.compile(r"\blinux\b|\bkernel\b|\bglibc\b|\bubuntu\b|\bdebian\b|red ?hat|\bsudo\b|systemd", re.I),
    "macos": re.compile(r"\bmacos\b|\bios\b|\bipados\b|\bwebkit\b|\bsafari\b|\bapple\b", re.I),
    "android": re.compile(r"\bandroid\b|\bpixel\b", re.I),
    "cloud": re.compile(r"\baws\b|amazon web services|\bazure\b|\bgcp\b|google cloud|kubernetes|\bs3\b|"
                        r"\bentra\b|microsoft 365|\boffice 365\b|\bsaas\b|\bcloud\b", re.I),
    "active_directory": re.compile(r"active directory|\bkerberos\b|domain controller|\bad cs\b|\badcs\b|"
                                   r"\bldap\b|netlogon|group policy", re.I),
    "identity": re.compile(r"\boauth\b|\bsaml\b|\boidc\b|openid|\bmfa\b|single sign-on|\bsso\b|\biam\b|"
                           r"\bentra id\b|\bokta\b|identity provider", re.I),
    "web": re.compile(r"\bweb\b|\bhttp\b|\bphp\b|wordpress|\bapache\b|\bnginx\b|\btomcat\b|\bjava\b|"
                      r"cross-site|\bxss\b|\bsql injection\b|\bcms\b|confluence|jenkins|browser|chrome", re.I),
    "network": re.compile(r"\brouter\b|\bfirewall\b|\bvpn\b|\bswitch\b|fortinet|fortigate|fortios|\bcisco\b|"
                          r"palo alto|pan-os|juniper|ivanti|citrix|netscaler|sonicwall|f5 big-ip|zyxel|"
                          r"\bgateway\b|draytek|tp-link|d-link|\bnetgear\b|\bcheck point\b", re.I),
}

# Products that are typically exposed to the Internet (used by the score).
INTERNET_FACING = re.compile(
    r"\bvpn\b|firewall|gateway|pan-os|globalprotect|fortios|fortigate|fortiweb|fortimanager|forticlient ems|"
    r"netscaler|citrix adc|ivanti connect|pulse connect|sonicwall|big-ip|exchange server|sharepoint|"
    r"confluence|jira|gitlab|jenkins|moveit|goanywhere|crushftp|wordpress|apache|nginx|tomcat|"
    r"\bweb server\b|\bmail server\b|zimbra|roundcube|outlook web|\bowa\b|remote desktop|\brdp\b|"
    r"\bssh\b|openssh|vcenter|esxi|horizon|workspace one|asa\b|ios xe|\brouter\b|edge device|"
    r"load balancer|screenconnect|connectwise|teamcity|veeam|papercut|citrix",
    re.I,
)


def normalize_cve(match: re.Match) -> str:
    return f"CVE-{match.group(1)}-{match.group(2)}"


def find_cves(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in CVE_RE.finditer(text or ""):
        seen[normalize_cve(m)] = None
    return list(seen)


def find_techniques(text: str) -> list[str]:
    return list(dict.fromkeys(TECHNIQUE_RE.findall(text or "")))


def classify_impact(text: str, cwes: list[str] | None = None) -> list[str]:
    tags = {tag for tag, rx in IMPACT_KEYWORDS.items() if rx.search(text or "")}
    for tag, ids in CWE_IMPACT.items():
        if cwes and ids.intersection(cwes):
            tags.add(tag)
    return sorted(tags)


def classify_platforms(text: str) -> list[str]:
    return sorted(p for p, rx in PLATFORM_KEYWORDS.items() if rx.search(text or ""))


@dataclass
class AttackDictionary:
    """Compiled matcher for ATT&CK group/software/campaign names and aliases."""

    version: str = "empty"
    # name(lower) -> list of (stix_id, obj_type, canonical name)
    names: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)
    technique_ids: dict[str, str] = field(default_factory=dict)  # T1059.001 -> stix_id
    cs_regex: re.Pattern | None = None  # case-sensitive (ambiguous names)
    ci_regex: re.Pattern | None = None  # case-insensitive (distinctive names)

    @classmethod
    def build(cls, session: Session) -> AttackDictionary:
        rows = session.execute(
            select(AttackObject.stix_id, AttackObject.obj_type, AttackObject.name, AttackObject.aliases,
                   AttackObject.external_id)
            .where(AttackObject.obj_type.in_(("group", "malware", "tool", "campaign", "technique")))
            .where(AttackObject.revoked.is_(False), AttackObject.deprecated.is_(False))
        ).all()
        version = str(session.scalar(select(func.max(AttackObject.modified))) or "empty") + f":{len(rows)}"
        d = cls(version=version)
        cs_terms, ci_terms = set(), set()
        for stix_id, obj_type, name, aliases, ext_id in rows:
            if obj_type == "technique":
                if ext_id:
                    d.technique_ids[ext_id] = stix_id
                continue
            for alias in {name, *(aliases or [])}:
                alias = (alias or "").strip()
                low = alias.lower()
                if len(alias) < 3 or low in NEVER_MATCH:
                    continue
                d.names.setdefault(low, [])
                if (stix_id, obj_type, name) not in d.names[low]:
                    d.names[low].append((stix_id, obj_type, name))
                if low in CASE_SENSITIVE_NAMES or len(alias) < 6:
                    cs_terms.add(alias)
                else:
                    ci_terms.add(alias)
        if cs_terms:
            d.cs_regex = _alternation(cs_terms, 0)
        if ci_terms:
            d.ci_regex = _alternation(ci_terms, re.IGNORECASE)
        return d

    def find(self, text: str) -> list[tuple[str, str, str, str]]:
        """Return (stix_id, obj_type, canonical_name, matched_text)."""
        found: dict[str, tuple[str, str, str, str]] = {}
        for rx in (self.ci_regex, self.cs_regex):
            if rx is None or not text:
                continue
            for m in rx.finditer(text):
                for stix_id, obj_type, name in self.names.get(m.group(0).lower(), []):
                    found.setdefault(stix_id, (stix_id, obj_type, name, m.group(0)))
        return list(found.values())


def _alternation(terms: set[str], flags: int) -> re.Pattern:
    ordered = sorted(terms, key=len, reverse=True)
    return re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in ordered) + r")(?![\w-])", flags)


_dict_lock = threading.Lock()
_dict_cache: AttackDictionary | None = None


def get_attack_dictionary(session: Session, refresh: bool = False) -> AttackDictionary:
    global _dict_cache
    with _dict_lock:
        if _dict_cache is None or refresh:
            _dict_cache = AttackDictionary.build(session)
        return _dict_cache


def reset_attack_dictionary() -> None:
    global _dict_cache
    with _dict_lock:
        _dict_cache = None


def snippet(text: str, needle: str, width: int = 120) -> str:
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return text[:width]
    start = max(0, idx - width // 2)
    return ("…" if start else "") + text[start: idx + len(needle) + width // 2].strip() + "…"
