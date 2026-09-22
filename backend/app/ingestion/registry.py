"""SOURCE_REGISTRY — the single source of truth for every data source.

Each endpoint below was verified (HTTP status + content type) on 2026-09-16
before being registered. See SOURCES.md for the full per-source documentation.

Tiers
  1  Government / vendor / original researcher / primary knowledge base
  2  Major security research organisations
  3  Security news
  4  Community / social / unverified (e.g. arbitrary GitHub repositories)

Methods (in order of preference): api, rss, stix, json, git, csv, sitemap, html
"""
from __future__ import annotations

from dataclasses import dataclass, field

MIN = 60
HOUR = 3600


@dataclass(frozen=True)
class SourceDef:
    key: str
    name: str
    homepage: str
    endpoint: str
    category: str  # vulnerability|attack|exploit|research|threat_intel|news|detection|ioc
    source_type: str  # human-readable, e.g. "Government Advisory"
    tier: int
    method: str
    interval: int
    phase: int = 1
    enabled_by_default: bool = True
    requires_auth: bool = False
    auth_env: str | None = None
    worker: str | None = None  # key of implementation in app.workers.WORKERS
    doc_type: str | None = None  # for feed sources: research|news|advisory
    rate_limit: str = ""
    fields: tuple[str, ...] = ()
    notes: str = ""
    max_bytes: int = 25 * 1024 * 1024
    extra: dict = field(default_factory=dict)


SOURCE_REGISTRY: list[SourceDef] = [
    # ---------------- Vulnerability intelligence ----------------
    SourceDef(
        key="cisa_kev", name="CISA Known Exploited Vulnerabilities",
        homepage="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        endpoint="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        category="vulnerability", source_type="Government Advisory", tier=1, method="json",
        interval=15 * MIN, worker="cisa_kev",
        rate_limit="No published limit; conditional GET (ETag/Last-Modified) used.",
        fields=("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
                "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes"),
        notes="Mirror: https://github.com/cisagov/kev-data. CSV also available.",
    ),
    SourceDef(
        key="nvd", name="NIST National Vulnerability Database",
        homepage="https://nvd.nist.gov/",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        category="vulnerability", source_type="Government Database", tier=1, method="api",
        interval=30 * MIN, worker="nvd", auth_env="NVD_API_KEY",
        rate_limit="5 requests / 30 s without key; 50 / 30 s with NVD_API_KEY.",
        fields=("id", "descriptions", "metrics(CVSS v4/v3.1/v3.0/v2, SSVC)", "weaknesses", "configurations(CPE)",
                "affected", "references", "published", "lastModified", "vulnStatus"),
        notes="Incremental sync via lastModStartDate/lastModEndDate (max 120-day window). Local cache per CVE.",
        max_bytes=80 * 1024 * 1024,
    ),
    SourceDef(
        key="cve_org", name="CVE.org (CVE Services)",
        homepage="https://www.cve.org/", endpoint="https://cveawg.mitre.org/api/cve/{cve_id}",
        category="vulnerability", source_type="CVE Program (CNA records)", tier=1, method="api",
        interval=24 * HOUR, worker=None,
        rate_limit="Public read endpoint; used only as a reference link, not polled.",
        fields=("cveMetadata", "containers.cna"),
        notes="Used for validation/reference links on CVE pages. Not polled in Phase 1.",
    ),
    # ---------------- MITRE ATT&CK ----------------
    SourceDef(
        key="mitre_attack", name="MITRE ATT&CK (Enterprise)",
        homepage="https://attack.mitre.org/",
        endpoint="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json",
        category="attack", source_type="Knowledge Base (STIX 2.1)", tier=1, method="stix",
        interval=6 * HOUR, worker="mitre_attack",
        rate_limit="GitHub raw content; checked against index.json version before downloading (~55 MB).",
        fields=("attack-pattern", "x-mitre-tactic", "intrusion-set", "malware", "tool", "campaign",
                "course-of-action", "x-mitre-data-source", "x-mitre-data-component",
                "x-mitre-detection-strategy", "x-mitre-analytic", "relationship"),
        notes="TAXII 2.1 alternative: https://attack-taxii.mitre.org/api/v21/ (requires Accept: application/taxii+json;version=2.1).",
        max_bytes=150 * 1024 * 1024,
    ),
    # ---------------- Exploit intelligence ----------------
    SourceDef(
        key="exploitdb", name="Exploit Database (OffSec)",
        homepage="https://www.exploit-db.com/",
        endpoint="https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        category="exploit", source_type="Exploit Archive", tier=2, method="git",
        interval=1 * HOUR, worker="exploitdb",
        rate_limit="GitLab raw file (~10 MB); conditional GET.",
        fields=("id", "description", "date_published", "author", "type", "platform", "codes", "tags",
                "date_added", "date_updated", "verified"),
        notes="The GitHub repo offensive-security/exploit-database is ARCHIVED (2022); official repo is on GitLab. "
              "Exploit code is never downloaded.",
    ),
    SourceDef(
        key="github", name="GitHub (PoC / research search)",
        homepage="https://github.com/", endpoint="https://api.github.com/search/repositories",
        category="exploit", source_type="Community Repository", tier=4, method="api",
        interval=1 * HOUR, worker="github", auth_env="GITHUB_TOKEN",
        rate_limit="Search API: 10 req/min unauthenticated, 30 req/min with GITHUB_TOKEN.",
        fields=("full_name", "html_url", "description", "stargazers_count", "language", "created_at",
                "pushed_at", "fork", "archived"),
        notes="Targeted queries only (prioritised CVEs + configured queries + watched repos). Never clones code.",
    ),
    # ---------------- Zero-day / vendor research ----------------
    SourceDef(
        key="project_zero", name="Google Project Zero",
        homepage="https://projectzero.google/", endpoint="https://projectzero.google/feed.xml",
        category="research", source_type="Original Researcher", tier=1, method="rss",
        interval=1 * HOUR, phase=2, enabled_by_default=False, worker="feed", doc_type="research",
        rate_limit="Static feed (~13 MB, full content); conditional GET.",
        notes="Legacy Blogspot feed redirects. Feed is large; enable when needed.",
        max_bytes=40 * 1024 * 1024,
    ),
    SourceDef(
        key="msrc", name="Microsoft Security Response Center",
        homepage="https://msrc.microsoft.com/",
        endpoint="https://api.msrc.microsoft.com/update-guide/rss",
        category="vulnerability", source_type="Vendor Advisory", tier=1, method="rss",
        interval=1 * HOUR, phase=2, enabled_by_default=False, worker="feed", doc_type="advisory",
        rate_limit="Public; CVRF API also available at https://api.msrc.microsoft.com/cvrf/v3.0/updates.",
        notes="Phase 2 will use the CVRF v3 API for Patch Tuesday structure and exploitation flags.",
        max_bytes=10 * 1024 * 1024,
    ),
    # ---------------- Threat intelligence ----------------
    SourceDef(
        key="unit42", name="Palo Alto Networks Unit 42",
        homepage="https://unit42.paloaltonetworks.com/", endpoint="https://unit42.paloaltonetworks.com/feed/",
        category="threat_intel", source_type="Security Research Organization", tier=2, method="rss",
        interval=1 * HOUR, worker="feed", doc_type="research",
    ),
    SourceDef(
        key="talos", name="Cisco Talos Intelligence",
        homepage="https://blog.talosintelligence.com/", endpoint="https://blog.talosintelligence.com/rss/",
        category="threat_intel", source_type="Security Research Organization", tier=2, method="rss",
        interval=1 * HOUR, worker="feed", doc_type="research",
        notes="Ghost-based blog; feed includes full content (~1 MB).",
    ),
    SourceDef(
        key="mandiant", name="Google Threat Intelligence (Mandiant)",
        homepage="https://cloud.google.com/blog/topics/threat-intelligence",
        endpoint="https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
        category="threat_intel", source_type="Security Research Organization", tier=2, method="rss",
        interval=1 * HOUR, phase=2, enabled_by_default=False, worker="feed", doc_type="research",
    ),
    SourceDef(
        key="sentinellabs", name="SentinelLabs",
        homepage="https://www.sentinelone.com/labs/", endpoint="https://www.sentinelone.com/labs/feed/",
        category="threat_intel", source_type="Security Research Organization", tier=2, method="rss",
        interval=1 * HOUR, phase=2, enabled_by_default=False, worker="feed", doc_type="research",
    ),
    SourceDef(
        key="crowdstrike", name="CrowdStrike Blog",
        homepage="https://www.crowdstrike.com/en-us/blog/", endpoint="https://www.crowdstrike.com/en-us/blog/feed",
        category="threat_intel", source_type="Security Research Organization", tier=2, method="rss",
        interval=1 * HOUR, phase=2, enabled_by_default=False, worker="feed", doc_type="research",
        notes="Feed mixes marketing and research posts.",
    ),
    SourceDef(
        key="qualys", name="Qualys Threat Research",
        homepage="https://blog.qualys.com/", endpoint="https://blog.qualys.com/feed",
        category="threat_intel", source_type="Security Research Organization", tier=2, method="rss",
        interval=1 * HOUR, phase=2, enabled_by_default=False, worker="feed", doc_type="research",
        notes="Feed mixes product and research posts.",
    ),
    # ---------------- Security news ----------------
    SourceDef(
        key="bleepingcomputer", name="BleepingComputer",
        homepage="https://www.bleepingcomputer.com/", endpoint="https://www.bleepingcomputer.com/feed/",
        category="news", source_type="Security News", tier=3, method="rss",
        interval=30 * MIN, worker="feed", doc_type="news",
        rate_limit="robots.txt Crawl-delay 2–10 s; one feed request per interval.",
    ),
    SourceDef(
        key="krebs", name="Krebs on Security",
        homepage="https://krebsonsecurity.com/", endpoint="https://krebsonsecurity.com/feed/",
        category="news", source_type="Security News", tier=3, method="rss",
        interval=30 * MIN, worker="feed", doc_type="news",
        rate_limit="robots.txt Crawl-delay 35 s; one feed request per interval.",
        notes="Served with Content-Type text/html but body is valid RSS 2.0.",
    ),
    SourceDef(
        key="therecord", name="The Record (Recorded Future News)",
        homepage="https://therecord.media/", endpoint="https://therecord.media/feed",
        category="news", source_type="Security News", tier=3, method="rss",
        interval=30 * MIN, worker="feed", doc_type="news",
    ),
    # ---------------- Detection intelligence ----------------
    SourceDef(
        key="sigma", name="SigmaHQ rules",
        homepage="https://sigmahq.io/", endpoint="https://api.github.com/repos/SigmaHQ/sigma/releases/latest",
        category="detection", source_type="Community Detection Rules (curated)", tier=2, method="git",
        interval=6 * HOUR, phase=2, enabled_by_default=False, worker=None,
        notes="Phase 2: download release rule archive, parse YAML (no execution), map tags attack.tXXXX.",
    ),
    SourceDef(
        key="yara", name="YARA (VirusTotal)",
        homepage="https://virustotal.github.io/yara/", endpoint="https://api.github.com/repos/VirusTotal/yara/releases/latest",
        category="detection", source_type="Tooling", tier=2, method="git",
        interval=6 * HOUR, phase=2, enabled_by_default=False, worker=None,
        notes="Engine repo only (no rules). Phase 2: track releases + curated rule repos via GITHUB_WATCH_REPOS.",
    ),
    # ---------------- Malware / IOC ----------------
    SourceDef(
        key="otx", name="AlienVault OTX",
        homepage="https://otx.alienvault.com/", endpoint="https://otx.alienvault.com/api/v1/pulses/subscribed",
        category="ioc", source_type="Community Threat Exchange", tier=4, method="api",
        interval=1 * HOUR, phase=2, enabled_by_default=False, requires_auth=True, auth_env="OTX_API_KEY",
        notes="Returns 403 without X-OTX-API-KEY.",
    ),
    SourceDef(
        key="malwarebazaar", name="MalwareBazaar (abuse.ch)",
        homepage="https://bazaar.abuse.ch/", endpoint="https://bazaar.abuse.ch/export/csv/recent/",
        category="ioc", source_type="Malware Repository (metadata only)", tier=2, method="csv",
        interval=1 * HOUR, phase=2, enabled_by_default=False,
        notes="API (mb-api.abuse.ch) now requires Auth-Key (401 without). CSV export is public. "
              "Sample download is NOT implemented (MALWARE_DOWNLOAD_ENABLED=false).",
    ),
    SourceDef(
        key="urlhaus", name="URLhaus (abuse.ch)",
        homepage="https://urlhaus.abuse.ch/", endpoint="https://urlhaus.abuse.ch/downloads/csv_recent/",
        category="ioc", source_type="Malicious URL Database", tier=2, method="csv",
        interval=1 * HOUR, phase=2, enabled_by_default=False,
        notes="API (urlhaus-api.abuse.ch) now requires Auth-Key (401 without). CSV dump is public.",
    ),
    SourceDef(
        key="virustotal", name="VirusTotal",
        homepage="https://www.virustotal.com/", endpoint="https://www.virustotal.com/api/v3/",
        category="ioc", source_type="Multi-scanner / Enrichment", tier=2, method="api",
        interval=24 * HOUR, phase=2, enabled_by_default=False, requires_auth=True, auth_env="VIRUSTOTAL_API_KEY",
        notes="On-demand lookup of hashes/domains/IPs/URLs only. Files are NEVER uploaded.",
    ),
]

REGISTRY_BY_KEY: dict[str, SourceDef] = {s.key: s for s in SOURCE_REGISTRY}


def get_source(key: str) -> SourceDef:
    return REGISTRY_BY_KEY[key]
