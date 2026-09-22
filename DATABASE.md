# Database

PostgreSQL 16. Models: `backend/app/models.py`. JSON columns use `JSONB` on
PostgreSQL and plain `JSON` on SQLite (the test suite runs on SQLite, so the
whole stack is testable without a database server).

Phase 1 creates the schema with `Base.metadata.create_all` at startup. Adding
Alembic is the first task before any schema change that must preserve data.

---

## Entity model

```
                     ┌────────────────────┐
                     │  vulnerabilities   │  canonical CVE (one row per CVE)
                     └─────────┬──────────┘
        ┌──────────────────────┼───────────────────────┐
        │                      │                       │
┌───────▼─────────┐  ┌─────────▼────────┐   ┌──────────▼─────────┐
│affected_products│  │source_references │   │    entity_links    │
│ vendor/product/ │  │ every URL that   │   │ explainable edges  │
│ CPE/versions    │  │ contributed data │   │ (method+evidence)  │
└─────────────────┘  └──────────────────┘   └──────────┬─────────┘
                                            ┌──────────┴──────────┐
                                  ┌─────────▼────────┐  ┌─────────▼────────┐
                                  │    documents     │  │     exploits     │
                                  │ research / news  │  │ Exploit-DB /     │
                                  │ advisory / repo  │  │ GitHub PoCs      │
                                  └──────────────────┘  └──────────────────┘

┌──────────────────┐    ┌────────────────────────┐
│  attack_objects  │◄───│  attack_relationships  │   local MITRE ATT&CK copy
└──────────────────┘    └────────────────────────┘

┌──────────┐  ┌────────────────┐  ┌─────────────┐  ┌────────────┐
│ sources  │  │ ingestion_runs │  │ http_cache  │  │ nvd_cache  │
└──────────┘  └────────────────┘  └─────────────┘  └────────────┘
```

---

## `vulnerabilities` — the canonical CVE

One row per CVE regardless of how many sources report it. This is the
duplicate-detection strategy: CISA, NVD, Microsoft, Unit 42, Talos,
BleepingComputer and GitHub all attach to the *same* row.

| Column | Type | Source | Notes |
|---|---|---|---|
| `cve_id` | PK, str | — | `CVE-YYYY-NNNNN`, validated by regex |
| `title`, `description` | text | KEV / NVD | first non-empty wins; NVD description preferred |
| `vuln_status` | str | NVD | e.g. `Analyzed`, `Awaiting Analysis` |
| `published`, `last_modified` | tz datetime | NVD | upstream dates |
| `first_seen`, `updated_at` | tz datetime | local | when *this* system saw/changed it |
| `cvss_score/_severity/_vector/_version` | float/str | NVD | Primary metric preferred, v4→v3.1→v3.0→v2 |
| `ssvc_exploitation` | str | NVD (CISA ADP) | `none` \| `poc` \| `active` — structured exploitation signal |
| `ssvc_automatable`, `ssvc_technical_impact` | str | NVD | |
| `cwes` | json[str] | NVD / KEV | |
| `vendor`, `product` | str | KEV first, else NVD | primary pair, for tables and filters |
| `in_kev`, `kev_*` | bool / mixed | CISA KEV | date added, due date, required action, ransomware use, notes |
| **Derived** | | `services/correlation.recompute_vulnerability` | |
| `actively_exploited` | bool | KEV ∪ SSVC `active` ∪ reports | |
| `has_exploit`, `exploit_count` | bool/int | Exploit-DB | |
| `has_poc`, `poc_count` | bool/int | GitHub, SSVC `poc` | |
| `source_count` | int | | distinct independent sources (CVE.org excluded — it mirrors the CNA record) |
| `tags` | json[str] | description + CWE | `rce`, `privilege_escalation`, `auth_bypass`, `sqli`, `path_traversal`, `memory_corruption`, `info_disclosure`, `dos` |
| `platforms` | json[str] | vendor/product/description | `windows`, `linux`, `macos`, `android`, `cloud`, `active_directory`, `identity`, `web`, `network` |
| `techniques` | json | explicit + heuristic | `[{"id":"T1190","method":"heuristic"}]` |
| `relevance_score` | int | scoring | 0–100 |
| `relevance_reasons` | json | scoring | `[{"factor","points","detail"}]` — the full explanation |
| `last_activity_at` | tz datetime | max of real-world signals | **used by every time filter** so "last 24h" means real activity, not collection time |
| `nvd_fetched_at`, `github_checked_at` | tz datetime | local | back-off bookkeeping |

Indexes: `published`, `first_seen`, `updated_at`, `last_activity_at`,
`relevance_score`, `in_kev`, `kev_date_added`, `actively_exploited`,
`has_exploit`, `has_poc`, `cvss_severity`, `vendor`, `product`.

## `entity_links` — the correlation graph

Every edge says *why* it exists.

| Column | Meaning |
|---|---|
| `subject_type` / `subject_id` | `document` \| `exploit` \| `vulnerability` |
| `object_type` / `object_id` | `cve` (CVE id) \| `attack` (STIX id) |
| `relation` | `mentions` \| `targets` \| `reports_exploitation` |
| `method` | `explicit` \| `regex` \| `dictionary` \| `co_mention` \| `heuristic` |
| `confidence` | `high` \| `medium` \| `low` (an article naming >5 CVEs is a roundup → `low`) |
| `source_key` | which source produced the edge |
| `evidence` | the text snippet that justified it |
| `observed_at` | publication date of the subject (drives "seen in window" queries) |

Unique on `(subject_type, subject_id, object_type, object_id, relation)` — re-ingestion never duplicates edges.

## `source_references` — provenance

Every URL that contributed data about a CVE, with `ref_type`
(`kev`, `nvd`, `cve_org`, `vendor_advisory`, `patch`, `mitigation`, `exploit`,
`reference`), upstream tags, `published_at` and `collected_at`. Unique per
`(cve_id, url)`. **The original URL is never discarded.**

## `documents` — research, news, advisories

`url` unique (canonicalised, tracking parameters stripped). Stores `title`, a
**≤600-character sanitised excerpt**, `doc_type`, `tier`, categories, authors,
`content_hash` (new vs. updated), `reports_exploitation`, `published_at`,
`collected_at`, `extraction_version` (which ATT&CK dictionary version parsed it).
A GIN full-text index over `title + summary` exists on PostgreSQL.

## `exploits` — exploits and PoCs

Unique `(source_key, external_id)` — EDB id, or `owner/repo` for GitHub.
`kind` ∈ `exploit` \| `poc` \| `scanner` \| `detection` \| `repository`;
plus platform, type, author, `verified`, `stars`, `language`, `cve_ids`, `tier`.

## `attack_objects` / `attack_relationships`

Local MITRE ATT&CK copy keyed by STIX id. `obj_type` ∈ technique, tactic, group,
malware, tool, campaign, mitigation, data_source, data_component,
detection_strategy, analytic. `extra` holds type-specific data (tactic order,
analytic log sources, detection-strategy analytic refs, campaign first/last
seen). Relationships are replaced atomically on each import.

## Operational tables

- **`sources`** — the registry plus runtime state: `enabled`, `interval_seconds`,
  `last_attempt`, `last_successful_fetch`, `last_status`, `last_error`,
  `items_fetched/new/updated`, `latency_ms`, `consecutive_failures`, and `state`
  (worker cursors, e.g. the NVD `last_mod_cursor`). Cursors are only persisted
  after a successful run.
- **`ingestion_runs`** — one row per run: status, counts, duration, error.
- **`http_cache`** — ETag / Last-Modified / SHA-256 per URL for conditional GETs.
- **`nvd_cache`** — raw NVD payload per CVE with `fetched_at` and a `found` flag,
  so unknown CVEs are not re-queried either.

---

## Query patterns

```sql
-- Actively exploited, highest priority first
SELECT cve_id, vendor, product, relevance_score
FROM vulnerabilities
WHERE actively_exploited AND last_activity_at > now() - interval '7 days'
ORDER BY relevance_score DESC;
```

```sql
-- Which independent sources talked about one CVE?
SELECT source_key, ref_type, url FROM source_references WHERE cve_id = 'CVE-2026-11111'
UNION ALL
SELECT source_key, relation, evidence FROM entity_links
WHERE object_type = 'cve' AND object_id = 'CVE-2026-11111';
```

```sql
-- CVEs co-mentioned with a threat actor in focused reports
SELECT DISTINCT l2.object_id
FROM entity_links l1
JOIN entity_links l2 ON l2.subject_id = l1.subject_id AND l2.subject_type = 'document'
WHERE l1.object_type = 'attack' AND l1.object_id = :group_stix_id
  AND l2.object_type = 'cve' AND l2.confidence = 'high';
```

## Backup

```bash
docker compose exec db pg_dump -U asber asber | gzip > asber-backup.sql.gz
```
