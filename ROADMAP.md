# Roadmap

What each phase actually requires, verified against the code rather than
restated from an older plan. The phase a source belongs to lives in
`backend/app/ingestion/registry.py`; the page for an unbuilt feature carries its
own specification in `frontend/app/<name>/page.tsx`.

---

## Phase 1 — done

CISA KEV, NVD (+SSVC), MITRE ATT&CK, Exploit-DB, GitHub, Unit 42, Talos,
BleepingComputer, Krebs, The Record. Dashboard, search, filters, CVE detail,
timeline, source health, exports, scheduled ingestion.

## Rampart — done

The owner's technology inventory, matched against the corpus with an
explainable state on every match, plus the research and news that reach it
through the CVEs they mention. See `DATABASE.md` and `SECURITY.md`.

---

## Phase 2

Twelve sources are registered, documented and visible on Source Health. They
split cleanly in two, and the split is the plan:

### Half of it needs no code

Six sources are RSS and already resolve to the generic `FeedWorker`
(`backend/app/workers/feed.py`). Verified by constructing each one:

| Source | Worker |
|---|---|
| `msrc` | FeedWorker |
| `mandiant` | FeedWorker |
| `sentinellabs` | FeedWorker |
| `crowdstrike` | FeedWorker |
| `qualys` | FeedWorker |
| `project_zero` | FeedWorker |

```bash
SOURCES_ENABLED=msrc,mandiant,sentinellabs,crowdstrike,qualys,project_zero
```

They have never been run here, so expect the ordinary first-contact problems —
a feed that moved, a field the parser did not anticipate — not missing code.

### The other half needs a worker each

`build_worker` raises for these: they have no implementation.

| Source | Method | What writing it involves |
|---|---|---|
| `sigma` | git | Clone the SigmaHQ release archive, parse rules as YAML. **Never execute a rule.** Map `logsource` and `tags` to ATT&CK techniques |
| `yara` | git | Same shape; YARA rules are parsed as text and stored, never compiled or run |
| `malwarebazaar` | csv | Public CSV export — sample *metadata* only. `MALWARE_DOWNLOAD_ENABLED` stays off |
| `urlhaus` | csv | Public CSV dump of malicious URLs |
| `otx` | api | AlienVault pulses, only when `OTX_API_KEY` is set |
| `virustotal` | api | On-demand lookups for a hash, domain, IP or URL. **Never submit a file** |

Two pages are waiting on these, and each already states what it will contain:

- **`/detection`** — Sigma and YARA rules mapped to ATT&CK and correlated with CVEs
- **`/iocs`** — hashes, domains, IPs and URLs, plus IOC → malware family → ATT&CK software

### Phase 2 of Rampart — measured, and not worth building

Vendor and product extraction from document text, so news reaches an
environment by naming a product rather than only through a CVE.

**The measurement says do not build it.** Taken on a 447-document corpus
against an inventory of FortiOS, Chrome and Windows Server:

| | |
|---|---|
| Documents already reaching the environment through CVE links | 147 |
| Documents mentioning "chrome" anywhere in their text | 109 |
| …of those, already arriving via a CVE link | 108 |
| **Documents product extraction would add** | **1** |

Security writing names the CVE. An article about a product almost always
cites the identifiers, so the link that already exists carries the signal, and
extraction would duplicate it.

The cost on the other side is real. A global dictionary would have to carry
10,302 distinct vendor/product pairs against roughly 800 ATT&CK objects, 35% of
them single words, with products genuinely named `access`, `core`, `edge`,
`go`, `office` and `word`. On the same corpus `access` matches 24 documents,
`one` 20 and `office` 9 — almost all of them the English word. The hand-curated
ambiguous-name policy in `services/extract.py` works at 800 names and does not
scale.

If this is ever revisited, the shape to build is the inverted one: search only
for the products the owner registered, which turns a 10,302-name dictionary
into a 20-name one. But the number to beat first is that single document.

**The lesson that actually mattered here:** the corpus was the bottleneck, not
the matching. Before the Phase 2 feeds were enabled, two documents reached the
environment. Enabling six RSS sources that needed no code took that to 147.

---

## Phase 3

Needs new models rather than new sources.

- **Watchlists with alerts.** Build on the `environments` table rather than
  beside it: a watchlist is an `environments` row with a different `kind`, and
  alerts hang off `environment_id`. That column exists for this.
- **Notification centre**, with pluggable delivery (Telegram / Discord / Slack /
  email) behind one notifier interface.
- **Daily briefing** (`/briefing`) — Critical / Exploited / New research /
  Trends, with trend detection comparing a window to the one before it.
- **Threat graph.**
- **Optional AI summaries**, where every sentence links back to the source it
  came from. `ai_provider` defaults to `none` and the guarantee is traceability,
  not fluency.

---

## Standing prerequisites

Neither is optional, and neither belongs to a numbered phase.

**Identity propagation, before a second environment owner.**
`api/deps.current_owner` returns a configured constant because the API cannot
tell callers apart — it trusts the internal network and the middleware in front
of it. Today the real access control for Rampart is the middleware, not the
API. `owner_id` is on every table from the first migration so the data model is
ready, but the *check* is not. See SECURITY.md.

**Alembic, before any deployment that is not this laptop.** The scheduler calls
`create_schema()` at startup, so a new table appears on a running instance
without the migration ever being applied, and a broken revision will not
announce itself by failing to boot. This repository's own database had no
`alembic_version` row at all until it was stamped. Verify migrations against a
database Alembic actually built; see DEPLOY.md.
