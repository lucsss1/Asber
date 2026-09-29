"""Request-scoped dependencies.

``current_owner`` is the single place that decides whose environment a request
is allowed to touch. Every Rampart query derives its ``owner_id`` from here and
from nowhere else, so the day identity arrives from the frontend this function
is the only thing that changes.
"""
from __future__ import annotations

from app.config import get_settings


def current_owner() -> str:
    """The owner this request acts as.

    Today this is a configured constant: the API trusts the internal network
    and has no way to tell one caller from another. It is written as a
    dependency rather than read inline so that the seam exists before it is
    needed — when identity propagation lands, only the body below changes and
    no query has to be revisited.

    Until then, a deployment must have exactly one Rampart owner. SECURITY.md
    records why.
    """
    return get_settings().rampart_owner
