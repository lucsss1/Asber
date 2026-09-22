# Contributing

## Development setup

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
cd frontend && npm install
```

Tests never touch the network — they run against fixtures in
`backend/tests/fixtures/` with a SQLite database:

```bash
cd backend && .venv/bin/python -m pytest -q
```

```bash
cd frontend && npx tsc --noEmit && npm run build
```

## Adding a source — the checklist

1. **Verify the access method before writing code.** In order of preference:
   official API → RSS/Atom → STIX/TAXII → public JSON → official repository →
   sitemap → HTML scraping (last resort). Check the real endpoint:

   ```bash
   curl -s -o /dev/null -w "%{http_code} %{content_type} %{size_download}\n" -A "asber-check/0.1" <URL>
   ```

   Also read `robots.txt` and the terms of service, and find the documented rate
   limit. Do not assume an endpoint exists because the website does.

2. **Register it** in `backend/app/ingestion/registry.py` with an honest `tier`,
   `phase`, `interval` (never aggressive), `rate_limit` note, the `fields` you
   collect and any caveat in `notes`.

3. **Implement the worker** in `backend/app/workers/`, or reuse `FeedWorker` if
   it is a normal RSS/Atom feed (then it is registry-only — no code).

   ```python
   class MySourceWorker(BaseWorker):
       key = "my_source"

       def sync(self, ctx: WorkerContext, stats: RunStats) -> None:
           resp = ctx.http.get(ctx.source.endpoint, session=ctx.session, conditional=True)
           if resp.not_modified:
               stats.not_modified = True
               return
           for row in parse(resp.json()):     # parsing lives in services/normalize.py
               stats.fetched += 1
               ...
               stats.touched_cves.add(cve_id)  # triggers recorrelation + rescoring
   ```

   Rules for workers:
   - parse in a **pure function** in `services/normalize.py` so it can be tested alone;
   - raise `MalformedRecord` for bad records — count and skip, never crash the run;
   - sanitise every string (`html_to_text`) and every URL (`safe_url`);
   - use conditional GET; call `ctx.checkpoint(stats)` in long loops;
   - set a per-host rate limit if the source documents one;
   - never download or execute code, and never fetch a URL that came from ingested data.

4. **Wire it** into `app/workers/__init__.py`.

5. **Add a fixture and tests.** A fixture in `tests/fixtures/` must include at
   least one *malformed* record. Cover: happy path, deduplication on re-run
   (`not_modified`), malformed input, and source failure (HTTP 500 → run marked
   `error`, other sources unaffected).

6. **Document it** in `SOURCES.md`: endpoint, method, auth, rate limit, interval,
   fields, transformation, deduplication strategy, failure behaviour.

## Code conventions

**Backend** — Python 3.12, type hints, ~110-column lines. Layering:
`workers/` (I/O) → `services/normalize.py` (pure parsing) →
`services/correlation.py` (merging, linking, scoring) → `api/` (read model).
Business logic never lives in a route handler.

**Frontend** — server components by default; `"use client"` only where genuinely
needed (currently just the sidebar). Filters are plain `GET` forms/links, so the
UI works without client-side JavaScript and every view is bookmarkable. Never
use `dangerouslySetInnerHTML`.

## Correlation & scoring changes

- Every edge must carry `method`, `confidence` and `evidence`. If you cannot say
  *why* two things are related, do not link them.
- Keep the distinction between **explicit** (a source said it) and **heuristic**
  (we inferred it) visible in the UI.
- Score weights belong in `WEIGHTS` in `services/scoring.py` and must produce a
  human-readable reason. Never add a hidden factor.

## Non-negotiables

Pull requests that execute PoCs, download malware samples, bypass a protection
mechanism, scrape a source that offers an API, or hide how a conclusion was
reached will not be accepted. See [SECURITY.md](SECURITY.md).
