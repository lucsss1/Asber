# Architecture

```
                    ┌───────────────────────────────────────────┐
                    │  Public sources (API / RSS / STIX / CSV)   │
                    └───────────────────────────────────────────┘
                                      │  polite HTTP (retry, backoff,
                                      │  rate limit, conditional GET)
                    ┌─────────────────▼─────────────────────────┐
  scheduler ──────► │  Workers (one per source, independent)     │
  (APScheduler)     │  cisa_kev · nvd · mitre_attack ·           │
                    │  exploitdb · github · feed×5               │
                    └─────────────────┬─────────────────────────┘
                                      │ normalise → sanitise → upsert
                    ┌─────────────────▼─────────────────────────┐
                    │  Correlation engine                        │
                    │  entity extraction · canonical CVE merge · │
                    │  explainable links · Threat Relevance      │
                    └─────────────────┬─────────────────────────┘
                                      │
                    ┌─────────────────▼─────────────────────────┐
                    │  PostgreSQL (unified model + full-text)     │
                    └─────────────────┬─────────────────────────┘
                                      │ read-only
                    ┌─────────────────▼─────────┐   ┌────────────────────┐
                    │  FastAPI  (JSON API)       │◄──│ Redis (locks +     │
                    └─────────────────┬─────────┘   │ manual triggers)   │
                                      │              └────────────────────┘
                    ┌─────────────────▼─────────────────────────┐
                    │  Next.js dashboard (server components)     │
                    └───────────────────────────────────────────┘
```

Four containers: `backend` (API), `scheduler` (ingestion), `db`, `redis`, plus
`frontend`. The API and the scheduler share the same image and codebase but run
different commands, so a slow ingestion run never blocks the UI.

---

## 1. Ingestion

### Source registry
`backend/app/ingestion/registry.py` is the single source of truth: key, name,
homepage, endpoint, category, **tier**, access method, interval, phase, auth
requirement, rate-limit note, collected fields and free-text notes. On startup
the registry is synced into the `sources` table, which then carries the runtime
state (enabled, cursor, freshness counters).

Access method preference, in order: **API → RSS/Atom → STIX/TAXII → public JSON
→ official repository → sitemap → HTML scraping**. No current source needs
scraping.

### HTTP client (`ingestion/http.py`)
One polite client used by every worker:

- per-host **rate limiting** (minimum interval between requests)
- **retries** with exponential backoff + jitter, honouring `Retry-After`
- **conditional GET**: ETag / Last-Modified stored in `http_cache`; an unchanged
  body (validated by SHA-256) short-circuits the whole run as `not_modified`
- **response size cap** (streamed, aborted if exceeded)
- **HTTPS-only** URL validation

Workers that process large payloads (Exploit-DB) defer storing the cache
validators until the last row is committed, so a mid-run failure does not make
the next run skip the file.

### Worker contract (`ingestion/base.py`)
A worker implements one method:

```python
def sync(self, ctx: WorkerContext, stats: RunStats) -> None
```

`run_worker` wraps it with everything else: an `ingestion_runs` record, the
freshness fields on `sources`, cursor persistence (only saved on success),
recomputation of touched CVEs, one structured JSON log line, and a `try/except`
that **isolates every failure to its own source**. Long workers call
`ctx.checkpoint(stats)` to commit progress incrementally.

```json
{"timestamp":"2026-09-16T18:22:03Z","level":"INFO","logger":"asber.ingestion",
 "message":"ingestion run","source":"cisa_kev","status":"success",
 "items_fetched":1713,"items_new":12,"items_updated":4,"items_malformed":0,
 "duration_ms":832,"error":null}
```

### Scheduling (`app/scheduler.py`)
One APScheduler interval job per enabled source (`coalesce`, `max_instances=1`,
jitter). On startup a **bootstrap** pass runs each stale source once, in
dependency order — MITRE ATT&CK first, so the name dictionary exists before
articles are parsed. A Redis lock prevents overlapping runs of the same source;
without Redis the scheduler falls back to in-process locks. A trigger poller
picks up manual runs requested through `POST /api/sources/{key}/run`. A
maintenance job recomputes time-decaying scores every 6 hours.

---

## 2. Normalisation

`services/normalize.py` turns source payloads into model fields as pure,
unit-testable functions. Malformed records raise `MalformedRecord`, are counted
and skipped — one bad row never aborts a run.

`services/sanitize.py` treats all external content as hostile: HTML is reduced
to plain text **at ingestion** (nh3, tags stripped), URLs are validated
(http/https only, tracking parameters removed), dates are parsed defensively.
No markup is ever stored, so no markup can ever be rendered.

---

## 3. Correlation

`services/correlation.py` is where the value is.

**Canonical entity.** A CVE is one row in `vulnerabilities`, no matter how many
sources mention it. KEV, NVD, Exploit-DB, GitHub and articles merge into it;
each contributor keeps its own row in `source_references` or `entity_links`,
preserving the original URL.

**Entity extraction** (`services/extract.py`) is deterministic: regexes for
CVE ids, ATT&CK technique ids and EDB ids; a dictionary built from the local
ATT&CK copy for group / malware / tool / campaign names and aliases. Ambiguous
names (`Net`, `Play`, `Royal`, `Cuba`…) are either never matched or matched only
with their exact ATT&CK capitalisation.

**Every edge is explainable.** `entity_links` records the relation, the
extraction `method` (explicit / regex / dictionary / co-mention / heuristic), a
`confidence`, the `source_key` and an `evidence` snippet. An article mentioning
more than five CVEs is treated as a roundup: its links are low-confidence and
never produce an actor attribution.

**ATT&CK mapping** comes in two clearly-labelled flavours: *explicit* (the
technique was named in a report about that CVE) and *heuristic* (derived from
impact and exposure, e.g. internet-facing + RCE → T1190). The UI marks heuristic
mappings with an asterisk and states the rationale.

**Threat Relevance** (`services/scoring.py`) is a plain weighted sum, capped at
100, that returns the list of factors that fired with their points and reasons.
Nothing is hidden, and the weights are visible in the UI.

---

## 4. API

FastAPI, read-only except for manual source triggers. Routers: dashboard /
search / sources / settings / metrics, vulnerabilities (+ export), content
(exploits, documents), attack. Extras: per-client rate limiting, security
headers, CORS restricted to the dashboard origin.

Search uses PostgreSQL full-text (`websearch_to_tsquery` + GIN index) and falls
back to `ILIKE` on SQLite, so the whole suite runs without PostgreSQL.

Opening an untracked CVE triggers an **on-demand** NVD lookup (cached in
`nvd_cache`), so any valid CVE id has a useful page.

---

## 5. Frontend

Next.js App Router with **server components**: the browser never talks to the
backend directly (only `/api/...` export downloads, proxied by Next), so no API
key can leak to the client. Filters are plain `GET` forms and links, which keeps
the UI bookmarkable, shareable and functional without client-side JavaScript.
External text is rendered as React children — never `dangerouslySetInnerHTML`.

---

## Design decisions

| Decision | Why |
|---|---|
| Separate API and scheduler processes | a 40-minute NVD backfill must not affect the UI |
| PostgreSQL full-text instead of Elasticsearch | dataset is small; one less moving part |
| Redis optional | the app must run with `docker compose up` and nothing else |
| Score stored, not computed per request | tables sort and filter on it; a job refreshes decay |
| Excerpts only (≤600 chars) | respects the publishers' copyright; full text is used transiently for extraction |
| Tiering on every source | the UI must not present news and government advisories as equally authoritative |
| `create_all` instead of Alembic | Phase 1 simplicity; Alembic is the first thing to add if the schema needs to evolve without a reset |
