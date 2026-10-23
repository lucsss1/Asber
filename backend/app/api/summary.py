"""The Overview's executive figures: distributions, not lists.

Everything here answers a question the reader can act on, and every shape was
chosen after measuring what the data actually looks like. Three candidates were
dropped because the measurement said a chart would show nothing:

- exploit availability across the environment is 2,532 / 17 / 10, so a pie
  would be ninety-nine per cent one slice;
- detection coverage is 4 of 2,559, so a meter would be an invisible sliver;
- both are reported as figures instead, where a small number reads as small.

What survived is three distributions with real spread. They are returned as
plain counts; the page decides how to draw them.

Scoped to the owner through ``deps.current_owner`` wherever it touches the
environment, like every other Rampart read.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import current_owner
from app.db import get_db
from app.models import EntityLink, EnvironmentAsset, EnvironmentMatch, Vulnerability
from app.services.rampart import matching, repository

router = APIRouter(prefix="/api/summary", tags=["dashboard"])

#: The order severity is read in, worst first. Anything the NVD did not score
#: is kept as its own class rather than folded into "low" — "we do not know how
#: bad this is" is not the same answer as "it is not bad".
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED")

#: What counts as reaching you. ``not_affected`` is excluded on purpose: it is
#: worth keeping as a record, but it is not part of "what is on my plate".
REACHING = (matching.AFFECTED, matching.POSSIBLY_AFFECTED)


def _reaching_cve_ids(session: Session, owner: str, environment_id: int):
    return select(EnvironmentMatch.cve_id).where(
        EnvironmentMatch.owner_id == owner,
        EnvironmentMatch.environment_id == environment_id,
        EnvironmentMatch.state.in_(REACHING),
    ).distinct()


@router.get("/environment")
def environment_summary(session: Session = Depends(get_db),
                        owner: str = Depends(current_owner)):
    """The three distributions the Overview draws, plus the figures it leads with."""
    env = repository.default_environment(session, owner)
    reaching = _reaching_cve_ids(session, owner, env.id)

    # 1. The verdict split. Genuine part-to-whole over three states, which is
    #    the one shape on this page a pie is honest for.
    by_state = dict(session.execute(
        select(EnvironmentMatch.state, func.count(func.distinct(EnvironmentMatch.cve_id)))
        .where(EnvironmentMatch.owner_id == owner,
               EnvironmentMatch.environment_id == env.id)
        .group_by(EnvironmentMatch.state)).all())
    verdict = [
        {"state": state, "label": label, "count": by_state.get(state, 0)}
        for state, label in (
            (matching.AFFECTED, "Affected"),
            (matching.POSSIBLY_AFFECTED, "To check"),
            (matching.NOT_AFFECTED, "Ruled out"),
        )
    ]

    # 2. How bad what reaches you actually is. An ordered scale, so it is drawn
    #    as columns on the project's own reserved severity colours rather than
    #    as a second palette for the same concept.
    # Grouped on the raw column and mapped afterwards. Grouping on a coalesce
    # puts a bound parameter in the GROUP BY, which PostgreSQL will not match
    # against the same expression in the SELECT.
    raw_sev = {
        (sev or "UNSCORED"): n
        for sev, n in session.execute(
            select(Vulnerability.cvss_severity, func.count())
            .where(Vulnerability.cve_id.in_(reaching))
            .group_by(Vulnerability.cvss_severity)).all()
    }
    severity = [{"severity": s, "count": raw_sev.get(s, 0)} for s in SEVERITY_ORDER]

    # 3. Which of your things carries the most. Magnitude, so one hue.
    assets = [
        {"id": a["id"], "label": a["label"], "product": a["product"],
         "affected": a["affected"], "possibly_affected": a["possibly_affected"]}
        for a in repository.counts_by_asset(session, owner, env.id)["assets"]
    ]

    # The figures. Each of these was a chart candidate the measurement killed.
    kev = session.scalar(
        select(func.count(func.distinct(Vulnerability.cve_id)))
        .where(Vulnerability.cve_id.in_(reaching), Vulnerability.in_kev.is_(True))) or 0
    exploited = session.scalar(
        select(func.count(func.distinct(Vulnerability.cve_id)))
        .where(Vulnerability.cve_id.in_(reaching), Vulnerability.has_exploit.is_(True))) or 0
    detectable = session.scalar(
        select(func.count(func.distinct(EntityLink.object_id)))
        .where(EntityLink.subject_type == "rule", EntityLink.object_type == "cve",
               EntityLink.object_id.in_(reaching))) or 0
    total = session.scalar(select(func.count()).select_from(reaching.subquery())) or 0

    session.commit()
    return {
        "environment": {"id": env.id, "name": env.name, "assets": len(assets)},
        "reaching": total,
        "verdict": verdict,
        "severity": severity,
        "assets": assets,
        "figures": {
            "in_kev": kev,
            "has_public_exploit": exploited,
            "has_detection_rule": detectable,
            "total": total,
        },
    }


@router.get("/corpus")
def corpus_summary(session: Session = Depends(get_db)):
    """The same shape for the whole corpus, for the reader with no inventory yet.

    Without this the Overview's charts are empty until Rampart is populated,
    which makes a first run look broken rather than unconfigured.
    """
    raw = {
        (sev or "UNSCORED"): n
        for sev, n in session.execute(
            select(Vulnerability.cvss_severity, func.count())
            .group_by(Vulnerability.cvss_severity)).all()
    }
    return {
        "severity": [{"severity": s, "count": raw.get(s, 0)} for s in SEVERITY_ORDER],
        "total": sum(raw.values()),
    }
