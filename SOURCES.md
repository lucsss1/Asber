# Source Registry

Every endpoint below was probed (HTTP status, content type, payload shape)
on **2026-09-16** before being registered. The registry lives in
`backend/app/ingestion/registry.py`; this document is its prose companion.

## Tiers

The dashboard does **not** treat all sources as equally reliable:

| Tier | Meaning | Examples |
|---|---|---|
| 1 | Government, vendor PSIRT, original researcher, primary knowledge base | CISA KEV, NVD, CVE.org, MITRE ATT&CK, MSRC, Project Zero |
| 2 | Major security research organisation | Unit 42, Talos, Mandiant, SentinelLabs, CrowdStrike, Qualys, Exploit-DB, abuse.ch |
| 3 | Security news (context layer, not a primary technical fact) | BleepingComputer, Krebs, The Record |
| 4 | Community / unverified | arbitrary GitHub repositories |

Tier is shown next to every source in the UI and is preserved in exports.

## Access-method policy

For each source: official API → RSS/Atom → STIX/TAXII → public JSON → official
repository → sitemap → **HTML scraping only as a last resort**. No source
currently requires scraping. `robots.txt`, terms of service and rate limits are
respected; no CAPTCHA, paywall, authentication or anti-bot control is bypassed.

---

# Phase 1 — implemented

## cisa_kev — CISA Known Exploited Vulnerabilities
- **Homepage** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Endpoint** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (verified 200, `application/json`, ~1.7 MB, 1,713 entries)
- **Method** public JSON · **Tier** 1 · **Auth** none · **Interval** 15 min
- **Rate limit** none published; conditional GET (ETag/Last-Modified) means an unchanged catalog costs one 304
- **Fields** `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `cwes`, `notes`
- **Transformation** → canonical `vulnerabilities` row (`in_kev`, KEV block, vendor/product, CWE); advisory URLs parsed out of `notes` become `source_references` of type `vendor_advisory`; NVD/BOD links are dropped as non-advisory
- **Deduplication** primary key `cve_id`; re-runs update in place
- **Failure behaviour** run marked `error`, `consecutive_failures` incremented, previous data untouched; malformed rows counted and skipped
- **Notes** mirror at https://github.com/cisagov/kev-data. New fields observed in 2026: `knownRansomwareCampaignUse`, `forensicTriage`, `cwes`

## nvd — NIST National Vulnerability Database
- **Endpoint** `https://services.nvd.nist.gov/rest/json/cves/2.0` (verified 200)
- **Method** official REST API · **Tier** 1 · **Auth** optional `NVD_API_KEY` · **Interval** 30 min
- **Rate limit** 5 requests / 30 s anonymous (client uses 6.5 s spacing), 50 / 30 s with a key (0.8 s)
- **Fields** descriptions, `metrics` (CVSS v4/v3.1/v3.0/v2 **and SSVC**), `weaknesses` (CWE), `configurations` (CPE), `affected` (CNA vendor/product/versions), `references` with tags, `published`, `lastModified`, `vulnStatus`
- **Transformation** CVSS: prefers the NVD *Primary* metric; SSVC: `exploitation` (`active`/`poc`/`none`), `automatable`, `technicalImpact` — `active` counts as exploitation evidence and `poc` as PoC evidence in the score. References are typed (vendor advisory / patch / exploit / mitigation)
- **Sync strategy** incremental by `lastModStartDate`/`lastModEndDate` (max 120-day window, cursor in `sources.state`), paginated at 2,000 per page with a checkpoint per page. CVEs published within `NVD_TRACK_DAYS` start being tracked; known CVEs are always updated. A second phase enriches KEV / high-relevance / recently-referenced CVEs one by one
- **Cache** `nvd_cache` per CVE (`NVD_CACHE_DAYS`, default 7) — the same CVE is never re-queried within that window, including for on-demand page loads
- **Failure behaviour** cursor only advances on success, so no window is ever skipped
- **Note** the 2026 API includes a top-level `affected` array that the original 2.0 documentation did not; both it and `configurations` are parsed

## cve_org — CVE.org (CVE Services)
- **Endpoint** `https://cveawg.mitre.org/api/cve/{cve_id}` (verified 200)
- **Method** API · **Tier** 1 · **Interval** not polled in Phase 1
- **Use** validation/reference link on every CVE page. Excluded from the "independent sources" count because it mirrors the same CNA record as NVD

## mitre_attack — MITRE ATT&CK Enterprise
- **Endpoint** `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json` → versioned bundle (verified: index 200; bundle 200, ~53 MB, **v19.2**)
- **Method** STIX 2.1 · **Tier** 1 · **Interval** 6 h
- **Rate limit** GitHub raw; the index is checked first and the bundle is downloaded **only when the version/modified marker changed**
- **Fields** `attack-pattern` (techniques/sub-techniques), `x-mitre-tactic`, `intrusion-set` (groups), `malware`, `tool`, `campaign`, `course-of-action` (mitigations), `x-mitre-data-source`, `x-mitre-data-component`, `x-mitre-detection-strategy`, `x-mitre-analytic`, relationships
- **Transformation** citations and markdown links stripped from descriptions; tactic order taken from `x-mitre-matrix.tactic_refs`; analytics keep their log-source references (e.g. `WinEventLog:Security EventCode=4768`)
- **Deduplication** STIX id as primary key; relationships replaced atomically per import
- **Note** ATT&CK v18+ replaced the free-text technique `detection` field with **detection strategies → analytics → log sources**; both are stored, new model preferred
- **Alternative** TAXII 2.1 at `https://attack-taxii.mitre.org/api/v21/` (verified — requires `Accept: application/taxii+json;version=2.1`). The STIX bundle was chosen: one conditional request instead of paginating ~25,000 objects

## exploitdb — Exploit Database (OffSec)
- **Endpoint** `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` (verified 200, ~10 MB)
- **Method** official repository file · **Tier** 2 · **Interval** 1 h
- **Fields** `id`, `description`, `date_published`, `author`, `type`, `platform`, `codes`, `tags`, `date_updated`, `verified`
- **Transformation** one `exploits` row per EDB id, linked to every CVE in `codes` (`targets`, high confidence). **Exploit code is never downloaded**
- **Deduplication** unique `(source_key, external_id)`; rows change only when `date_updated` differs; duplicate ids inside the file are guarded against
- **⚠ Important** the GitHub repository `offensive-security/exploit-database` is **archived** (last push 2022-11-10) and its raw CSV 404s. The official location is GitLab

## github — GitHub (PoC / research search)
- **Endpoint** `https://api.github.com/search/repositories` (verified 200)
- **Method** API · **Tier** 4 (unverified community) · **Auth** optional `GITHUB_TOKEN` · **Interval** 1 h
- **Rate limit** search: 10 req/min anonymous (6.5 s spacing), 30 req/min with a token (2.2 s); `X-RateLimit-Remaining: 0` and HTTP 403 stop the run gracefully instead of hammering
- **Queries** never indiscriminate. Per run: up to `GITHUB_MAX_CVES_PER_RUN` prioritised CVEs (KEV, relevance ≥ 50, or recent CVSS ≥ 8) not checked in `GITHUB_RECHECK_HOURS`, searched as `"CVE-…" in:name,description`; plus `GITHUB_EXTRA_QUERIES`; plus releases of `GITHUB_WATCH_REPOS`
- **Filtering** forks are ignored; a repository is kept only if it names the CVE in its name or description. Classified as `poc` / `detection` / `scanner` / `repository`
- **Failure behaviour** rate limiting is caught and the run ends successfully with a note
- **⚠ Safety** repositories are metadata only — never cloned, never executed. The UI always shows an "unverified community code" warning

## Feeds (generic RSS/Atom worker)

| Key | Source | Endpoint (verified 200) | Tier | Interval | Type |
|---|---|---|---|---|---|
| `unit42` | Palo Alto Unit 42 | `https://unit42.paloaltonetworks.com/feed/` | 2 | 1 h | research |
| `talos` | Cisco Talos | `https://blog.talosintelligence.com/rss/` | 2 | 1 h | research |
| `bleepingcomputer` | BleepingComputer | `https://www.bleepingcomputer.com/feed/` | 3 | 30 min | news |
| `krebs` | Krebs on Security | `https://krebsonsecurity.com/feed/` | 3 | 30 min | news |
| `therecord` | The Record | `https://therecord.media/feed` | 3 | 30 min | news |

- **Fields** title, link, summary/content, published date, categories, authors
- **Transformation** HTML → plain text at ingestion; **only a ≤600-character excerpt is stored** (copyright); the full entry text is used transiently to extract CVEs, ATT&CK ids and actor/malware names, then discarded. Tracking parameters are stripped from URLs
- **Deduplication** unique canonical URL; a content hash decides new vs. updated vs. unchanged
- **Failure behaviour** an unparseable feed fails only that source; entries without a link or title are counted as malformed and skipped
- **robots.txt** BleepingComputer declares `Crawl-delay` 2–10 s and Krebs 35 s — both are polled once per interval, far below those limits
- **Note** Krebs serves its feed as `text/html`; the body is valid RSS 2.0 and parses correctly

---

# Phase 2 — registered, documented, worker pending

These appear on the Source Health page as "not collecting" with their phase, so
nothing is silently missing.

| Key | Source | Endpoint | Verified | Blocking issue / plan |
|---|---|---|---|---|
| `msrc` | Microsoft MSRC | `https://api.msrc.microsoft.com/update-guide/rss` (+ CVRF v3 API) | 200, ~2.7 MB | Feed works with the generic worker (`SOURCES_ENABLED=msrc`); CVRF parsing for Patch Tuesday structure and exploitation flags is the real Phase 2 work |
| `project_zero` | Google Project Zero | `https://projectzero.google/feed.xml` | 200, ~13 MB | Works with the generic worker; large feed, so off by default |
| `mandiant` | Google/Mandiant | `https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/` | 200 | Enable via `SOURCES_ENABLED` |
| `sentinellabs` | SentinelLabs | `https://www.sentinelone.com/labs/feed/` | 200 | Enable via `SOURCES_ENABLED` |
| `crowdstrike` | CrowdStrike | `https://www.crowdstrike.com/en-us/blog/feed` | 200 | Mixed marketing/research; needs category filtering |
| `qualys` | Qualys | `https://blog.qualys.com/feed` | 200 | Mixed product/research; needs category filtering |
| `sigma` | SigmaHQ | `https://api.github.com/repos/SigmaHQ/sigma/releases/latest` | 200 | Download release archive, parse YAML (never execute), map `attack.tXXXX` tags to techniques |
| `yara` | YARA (VirusTotal) | `https://api.github.com/repos/VirusTotal/yara/releases/latest` | 200 | Engine repo only — contains no rules. Rule repositories go through `GITHUB_WATCH_REPOS` |
| `otx` | AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` | **403 without key** | Requires `OTX_API_KEY`; stays disabled without it |
| `malwarebazaar` | MalwareBazaar | `https://bazaar.abuse.ch/export/csv/recent/` | 200 (CSV) | The API (`mb-api.abuse.ch`) now returns **401 without an Auth-Key**; the public CSV export is the way in. **Sample download is not implemented and stays disabled** |
| `urlhaus` | URLhaus | `https://urlhaus.abuse.ch/downloads/csv_recent/` | 200 (CSV) | Same situation: `urlhaus-api.abuse.ch` returns 401; public CSV dump is used |
| `virustotal` | VirusTotal | `https://www.virustotal.com/api/v3/` | requires key | On-demand lookups of hashes/domains/IPs/URLs only. **Files are never uploaded** |

## Adding a source

Add a `SourceDef` to `SOURCE_REGISTRY`, implement a worker (or reuse
`FeedWorker`), register it in `app/workers/__init__.py`, add a fixture and a
test. See [CONTRIBUTING.md](CONTRIBUTING.md).
