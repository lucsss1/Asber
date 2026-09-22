"""Treat all external content as untrusted.

External HTML is reduced to plain text *at ingestion time* (no markup is ever
stored), and the frontend renders text only — never raw HTML.
"""
from __future__ import annotations

import html
import re
from datetime import date, datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import nh3
from dateutil import parser as dateparser

_WS = re.compile(r"\s+")
_BLOCK_TAGS = re.compile(r"(?i)<\s*(br|/p|/div|/li|/h[1-6]|/tr)\s*/?>")
_DROP_BLOCKS = re.compile(r"(?is)<\s*(script|style|noscript|iframe|object|template)\b.*?<\s*/\s*\1\s*>")
_TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "ref"}


def html_to_text(value: str | None, max_len: int | None = None) -> str:
    """Strip every tag and return normalised plain text."""
    if not value:
        return ""
    value = _DROP_BLOCKS.sub(" ", value)
    value = _BLOCK_TAGS.sub(" ", value)
    cleaned = nh3.clean(value, tags=set(), attributes={}, strip_comments=True)
    text = html.unescape(cleaned)
    # a second unescape could reintroduce "<" characters; that's fine because
    # this is plain text and the UI never renders it as HTML.
    text = _WS.sub(" ", text).strip()
    if max_len and len(text) > max_len:
        text = text[: max_len - 1].rsplit(" ", 1)[0] + "…"
    return text


def safe_url(value: str | None) -> str | None:
    """Return a normalised http(s) URL or None. Rejects javascript:, data:, etc."""
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if any(c in value for c in "\r\n\t <>\"'") :
        return None
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    query = urlencode([(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                       if k.lower() not in _TRACKING_PARAMS])
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def parse_dt(value) -> datetime | None:
    """Parse arbitrary date input into an aware UTC datetime (or None)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day)
    elif isinstance(value, (tuple, list)) and len(value) >= 6:  # feedparser struct_time
        try:
            dt = datetime(*value[:6])
        except (TypeError, ValueError):
            return None
    else:
        try:
            dt = dateparser.parse(str(value))
        except (ValueError, OverflowError, TypeError):
            return None
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_date(value) -> date | None:
    dt = parse_dt(value)
    return dt.date() if dt else None


def aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; normalise for comparisons."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def clip(value: str | None, n: int) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value[:n] if value else None
