"""Indicator parsing and normalisation — pure, no session, no I/O.

Nothing here fetches a sample, and nothing here submits one anywhere. The
abuse.ch feeds publish metadata; that is all Asber stores, and
``MALWARE_DOWNLOAD_ENABLED`` stays off.

The normalisation exists because the page is a lookup. A reader pasting a hash
from an alert will paste it in whatever case the alert used, and a reader
pasting a URL may paste the host alone. Both have to find the row.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

SHA256 = "sha256"
MD5 = "md5"
SHA1 = "sha1"
URL = "url"
DOMAIN = "domain"
IPV4 = "ipv4"

_HEX = {SHA256: re.compile(r"^[0-9a-f]{64}$"), SHA1: re.compile(r"^[0-9a-f]{40}$"),
        MD5: re.compile(r"^[0-9a-f]{32}$")}
_IPV4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")

#: Suffixes a feed attaches to a family name that ATT&CK does not carry.
#: Measured on the MalwareBazaar recent dump: stripping these lifts the match
#: from 10 families / 73 samples to 12 / 88. Modest, and it costs one regex.
_FAMILY_SUFFIX = re.compile(r"(rat|stealer|loader|bot|trojan|ransomware|miner)$")

#: Values a feed writes where it means "nothing".
_EMPTY = {"", "n/a", "none", "unknown", "null", "-"}

#: Tags that describe the file, not the family. URLhaus mixes both in one
#: list, and some of these collide with real ATT&CK software: ``PS1`` is
#: S0613, a loader, so a ``.ps1`` script tagged ``ps1`` resolved to it and
#: accounted for 142 of 675 matches on the recent dump -- a fifth of them
#: wrong. Excluding the formats costs nothing real: a format is not a family,
#: so a row that carries only formats should carry no family at all.
FORMAT_TAGS = frozenset({
    "exe", "dll", "ps1", "js", "jse", "vbs", "vbe", "bat", "cmd", "hta", "lnk",
    "elf", "apk", "jar", "msi", "scr", "zip", "rar", "7z", "gz", "tar", "iso",
    "img", "doc", "docx", "xls", "xlsx", "ppt", "rtf", "pdf", "sh", "py", "php",
    "html", "swf", "32-bit", "64-bit", "x86", "x64", "arm", "mips", "mipsel",
    "powershell", "office", "macro", "shellcode", "binary", "script", "text",
})


def classify(value: str) -> str | None:
    """What kind of observable this is, or None if it is not one we store."""
    v = (value or "").strip().lower()
    if not v:
        return None
    for kind, pattern in _HEX.items():
        if pattern.match(v):
            return kind
    if "://" in v:
        return URL
    if _IPV4.match(v):
        return IPV4 if all(0 <= int(p) <= 255 for p in v.split(".")) else None
    if _DOMAIN.match(v):
        return DOMAIN
    return None


def normalise(value: str) -> str:
    """The form a lookup compares against: trimmed and lowercased.

    A URL keeps its path, because two URLs on one host are two indicators; the
    host is extracted separately so a host-only search still finds them.
    """
    return (value or "").strip().lower()


def host_of(value: str) -> str | None:
    """The host part of a URL, or the value itself when it is already a host."""
    v = normalise(value)
    if not v:
        return None
    if "://" in v:
        netloc = urlsplit(v).netloc
        # strip credentials and port; keep IPv6 brackets out of the way
        netloc = netloc.rsplit("@", 1)[-1]
        if netloc.startswith("["):
            return netloc.split("]", 1)[0].lstrip("[") or None
        return (netloc.rsplit(":", 1)[0] if ":" in netloc else netloc) or None
    return v if classify(v) in (DOMAIN, IPV4) else None


def clean(value: str | None) -> str | None:
    """Upstream's own word, or None where it wrote a placeholder for nothing."""
    if value is None:
        return None
    v = " ".join(str(value).split()).strip('"').strip()
    return None if v.lower() in _EMPTY else v


def family_keys(family: str | None) -> list[str]:
    """Candidate names to match against ATT&CK, most specific first.

    ``remcosrat`` is Remcos with a suffix the feed added; ATT&CK carries only
    the base. Returning both, in order, keeps an exact hit winning over a
    stripped one.
    """
    name = clean(family)
    if not name:
        return []
    lowered = name.lower()
    if lowered in FORMAT_TAGS:
        return []
    out = [lowered]
    base = _FAMILY_SUFFIX.sub("", lowered)
    if base and base != lowered and len(base) >= 3:
        out.append(base)
    return out


def split_tags(raw: str | None) -> list[str]:
    """A feed's comma-separated tag field, cleaned and de-duplicated."""
    value = clean(raw)
    if not value:
        return []
    out: list[str] = []
    for tag in value.split(","):
        t = clean(tag)
        if t and t not in out:
            out.append(t)
    return out
