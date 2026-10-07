# Working on Asber

Asber is a personal cyber threat intelligence hub: it collects from public
sources, correlates, and prioritises. FastAPI + APScheduler + PostgreSQL behind
a Next.js App Router frontend with server components. It is **not** a news
aggregator — every view exists to answer an operational question.

Read `ARCHITECTURE.md`, `DATABASE.md` and `SECURITY.md` before changing
ingestion, the schema, or anything touching authentication. `ROADMAP.md` says
what each unbuilt phase actually requires, verified against the code.

---

## Hard rules

**Authorship.** Every commit, branch and pull request is published as
`lucsss1 <oliveira00904@gmail.com>`. No AI tool is named anywhere in the
repository, in commit messages, or in PR descriptions — no co-author trailers,
no "generated with" footers.

**Never** execute a collected PoC or exploit, download malware
(`MALWARE_DOWNLOAD_ENABLED` is off and stays off), bypass a CAPTCHA, paywall or
anti-bot control, or send a file to VirusTotal automatically.

**Security on every change.** OWASP Top 10:2025 is the checklist, and the
project tests it in two layers, because they catch different things:

- `backend/tests/test_security.py` — what is provable offline
- `scripts/security_scan.sh` — the assembled system's edge configuration

The two findings that would have shipped (`/api/<anything>.png` skipping auth,
`/api/auth/*` swallowed by the proxy) were both caught by attacking the running
stack, not by reading code.

**Explainability is a feature, not a nicety.** The Threat Relevance Score shows
its factors; ATT&CK mappings say whether they were stated or inferred; a Rampart
match carries the sentence behind its verdict. A verdict the reader cannot
interrogate is not worth shipping.

---

## Running it

```bash
docker compose up -d --build          # the whole stack, http://localhost:3000
docker compose up -d --build backend  # backend only — code is baked into the
                                      # image, so `restart` will NOT pick up edits
```

Tests (currently **229 backend**, **8 frontend**):

```bash
# backend — source is not in the image, so mount it
MSYS_NO_PATHCONV=1 docker compose run --rm --no-deps \
  -v "$(pwd -W)/backend:/src" -w //src --entrypoint sh backend \
  -c "pip install -q pytest; python -m pytest tests/ -q"

cd frontend && npm test && npx tsc --noEmit
```

The frontend has no test framework on purpose: `npm test` runs `node --test`
with native TypeScript stripping. Do not add vitest or jest for a handful of
pure functions.

Docker Desktop exits when launched non-interactively; start it from PowerShell
with `Start-Process` and poll `docker info` rather than assuming it is up.

---

## Verification

**A 200 does not prove a page is correct.** This has been learned the expensive
way here: the dashboard shell once vanished entirely while every route still
returned 200. Look at the rendered page.

**Prefer the Playwright MCP over the built-in browser pane for verification.**
The pane intermittently stops painting and returns false readings —
`innerWidth: 0`, animations frozen on their first frame, a 197px element
measured as 0. One of those nearly caused a pointless rewrite of the whole
threat table. Playwright also reports the console, which is how the missing
favicon was found.

**Measure before concluding.** Twice in this project a confident diagnosis was
wrong and the measurement was right. When a reading looks impossible, suspect
the instrument.

---

## Design system

The visual language is an instrument, not a publication. The rules are load
bearing, not taste:

- **Warm means threat, cool means interface.** Red, orange and amber belong to
  the risk scale alone. If something warm is on screen, something is wrong. The
  interface accent is cool so it can never be mistaken for an alarm.
- **Two voices.** Sans (Inter) for everything you read and operate; mono (IBM
  Plex Mono) **only for data you might copy or compare** — ids, dates, CVSS
  vectors, scores. Mono is not decoration, and it does not set labels.
- **Quiet at rest, deep on touch.** Less on screen by default; depth revealed
  in place. The threat table shows four columns and keeps the rest one press
  away, fetched on demand.
- **Tracking is size-specific** (`--track-display` / `--track-body` /
  `--track-label`). One value for every size is wrong at most of them.
- Motion follows the animation gate: press feedback and state changes yes;
  entry choreography on anything read dozens of times a day, no. The command
  palette has **no** open animation on purpose.

Full tokens and the reasoning live at the top of `frontend/app/globals.css`.

---

## Rampart (`backend/app/services/rampart/`, `frontend/app/rampart/`)

The owner's technology inventory, matched against the corpus.

- **Doubt resolves downwards.** `affected` requires a version that was parsed
  *and* compared against a bound that was also parsed. Everything else is
  `possibly_affected`. Saying "you are safe" because a version string could not
  be read is the one failure this must never have.
- **One door for scoping.** `services/rampart/repository.py` is the only module
  that builds a query against the Rampart tables, and every function takes
  `owner` first. Routers never write their own statement.
- **`relevance_score` is shared and untouched.** Environment exposure is a
  separate stored number on `environment_matches`.
- The API cannot distinguish callers; `api/deps.current_owner` returns a
  configured constant. **One owner per deployment** until identity is
  propagated from the frontend. See SECURITY.md.

---

## Traps already hit here

- **`create_schema()` runs at scheduler startup**, so a new table appears
  without the migration ever being applied and a broken revision will not
  announce itself. Verify migrations against a database Alembic actually built.
  The production database had no `alembic_version` row at all until it was
  stamped.
- **SQLite does not enforce foreign keys**, so `ON DELETE CASCADE` works in
  Postgres and silently does nothing under test. Delete dependent rows
  explicitly.
- **GitHub closes a child PR when its base branch is deleted** — it does not
  retarget. In a stacked series, retarget every PR to `main` *before* merging
  the one below it.
- **`affected_products.versions` is a display string**, not structured bounds
  (`">= 7.0.0 < 7.2.9"`). Only 52% of rows carry a CPE, and real values include
  `Hh-B20211125.1046`.
- Git Bash mangles paths in Docker arguments; prefix with `MSYS_NO_PATHCONV=1`
  and use `$(pwd -W)`.

---

## Open work

See `ROADMAP.md` for the full picture. The decisions that are still the user's
to make:

- **Rampart Phase 2** (vendor/product extraction from documents) was measured
  and dropped: on a 447-document corpus it would have added **one** document
  that was not already arriving through a CVE link. Security writing names the
  CVE, so the existing link already carries the signal. See `ROADMAP.md`.
- **The threat view does not group by asset.** With three assets the
  environment already carries over a thousand matches, and the page lists CVEs
  rather than "what is wrong with each thing I have". This gets unreadable
  before it gets wrong.
