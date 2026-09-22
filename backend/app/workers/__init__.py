"""Worker implementations, one per source (see app.ingestion.registry)."""
from __future__ import annotations

from app.ingestion.base import BaseWorker
from app.ingestion.registry import REGISTRY_BY_KEY


def build_worker(key: str) -> BaseWorker:
    sdef = REGISTRY_BY_KEY[key]
    if sdef.worker == "cisa_kev":
        from app.workers.cisa_kev import CisaKevWorker
        return CisaKevWorker()
    if sdef.worker == "nvd":
        from app.workers.nvd import NvdWorker
        return NvdWorker()
    if sdef.worker == "mitre_attack":
        from app.workers.mitre_attack import MitreAttackWorker
        return MitreAttackWorker()
    if sdef.worker == "exploitdb":
        from app.workers.exploitdb import ExploitDbWorker
        return ExploitDbWorker()
    if sdef.worker == "github":
        from app.workers.github import GithubWorker
        return GithubWorker()
    if sdef.worker == "feed":
        from app.workers.feed import FeedWorker
        return FeedWorker(key)
    raise KeyError(f"source {key!r} has no worker implementation yet (phase {sdef.phase})")


def implemented_keys() -> list[str]:
    return [k for k, s in REGISTRY_BY_KEY.items() if s.worker]
