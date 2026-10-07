# Security

This is a cybersecurity tool that ingests hostile content by design. The rules
below are enforced in code, not just documented.

## Hard rules

| Rule | Where it is enforced |
|---|---|
| **Never execute a PoC, exploit or any external code** | Nothing in the codebase runs a subprocess on collected data. Exploit-DB and GitHub contribute *metadata only*; no repository is ever cloned |
| **Never download malware samples** | No worker fetches a sample. `MALWARE_DOWNLOAD_ENABLED` defaults to `false` and has no implementation behind it — the flag exists so the intent is explicit |
| **Never upload your files anywhere** | VirusTotal support (Phase 2) is lookup-only: hashes, domains, IPs, URLs. File submission is not implemented |
| **Never bypass protections** | No CAPTCHA solving, no paywall circumvention, no anti-bot evasion, no authentication bypass. A source that requires a key stays disabled until you provide one |
| **Treat every external byte as untrusted** | See below |

## Untrusted content handling

**HTML never reaches the database.** Feed content is reduced to plain text at
ingestion with `nh3` (all tags stripped, comments removed), after `<script>`,
`<style>`, `<iframe>` and `<object>` blocks are dropped. Nothing stored is
markup, so nothing rendered can be markup.

**The frontend never renders raw HTML.** There is no `dangerouslySetInnerHTML`
anywhere; external text is passed as React children, which escapes it. A
Content-Security-Policy header is set, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and every
external link carries `rel="noopener noreferrer nofollow"`.

**URLs are validated.** Only `http`/`https` with a host survive `safe_url`;
`javascript:`, `data:`, `file:`, `ftp:` and URLs containing control characters
are dropped. Outbound requests are HTTPS-only.

**Exports are escaped too.** Markdown export escapes `[ ] ( ) < > # | * _ \``
so a malicious article title cannot inject a link or HTML into an exported
report; CSV export prefixes `= + - @ TAB CR` cells to neutralise spreadsheet
formula injection. Both behaviours are covered by tests.

**Malformed input is contained.** Every parser validates shape and raises
`MalformedRecord`; bad records are counted and skipped, never crashing a run.
Responses have a size cap and are streamed. Feed XML is parsed by `feedparser`,
whose SAX backend has external entity resolution disabled (no XXE).

**Injection.** All database access goes through SQLAlchemy with bound
parameters; user-supplied `LIKE` terms are escaped. Filter values are validated
against allow-lists.

## Secrets

- Every credential is optional; the app runs fully without any.
- Secrets are `SecretStr` and never logged.
- `GET /api/settings` returns **booleans only** (`"NVD_API_KEY": false`) — no
  value is ever sent to the browser. A test asserts this.
- The frontend fetches server-side, so no key can reach client JavaScript.
- `.env` is git-ignored; only `.env.example` is committed.

## Least privilege

- Both images run as a non-root user (uid 10001 / 10002).
- PostgreSQL and Redis are **not** published to the host — only the application
  containers reach them.
- **Locally** the API and dashboard bind to `127.0.0.1` and there is no
  authentication: on a personal machine the operating system is the access
  control. **Deployed** (see [DEPLOY.md](DEPLOY.md)) the API has no public
  address at all, and every request to the dashboard passes an OAuth session
  check plus an explicit e-mail allowlist before anything is proxied.
- The API is read-only apart from `POST /api/sources/{key}/run`, which only
  queues an already-registered source; it accepts no user-supplied URL.
- A per-client rate limit protects the API even locally.

## Being a good citizen

Rate limits, `robots.txt` and terms of service are respected; conditional
requests avoid re-downloading unchanged data; retries use exponential backoff
and honour `Retry-After`; the `User-Agent` identifies the tool and is
configurable. Only excerpts of third-party articles are stored, always with the
original URL — full-text copies are used transiently for entity extraction and
discarded.

## Testing, per change

Every change is checked against the **OWASP Top 10:2025** before it ships. Two
layers, because they prove different things.

**1. Automated, in the test suite** — `backend/tests/test_security.py`

```bash
cd backend && python -m pytest tests/test_security.py -v
```

Covers what can be proven without a deployment: injection is inert (a working
injection would return every row; a bound parameter returns none), external HTML
never survives ingestion, dangerous URL schemes are dropped, exports cannot
inject links or spreadsheet formulas, secrets never reach a log or a response,
malformed input fails with a typed error instead of a stack trace, and a bad
record never aborts a collection run.

**2. Against a running deployment** — `scripts/security_scan.sh`

```bash
./scripts/security_scan.sh https://your-domain
./scripts/security_scan.sh https://localhost -k   # local, private CA
```

Covers what only exists once the stack is assembled: that the API really is
unreachable without a session, that known middleware bypasses fail, that TLS
and the security headers are applied, and that the sign-in flow is reachable.
Exit code 0 means every check passed.

**3. Dependencies**

```bash
cd backend && python -m pip_audit -r requirements.txt
cd frontend && npm audit --omit=dev
```

Run before every deployment. A03 (Software Supply Chain Failures) moved up to
third place in the 2025 list for good reason: the most likely vulnerability in
this project is one you inherited, not one you wrote.

### What this testing has already caught

| Finding | Category | Status |
|---|---|---|
| `/api/<anything>.png` skipped authentication and reached the backend | A01 | Fixed |
| `/api/auth/*` was swallowed by the backend proxy, so sign-in could never complete | A07 | Fixed |
| Next.js 15.5.4 carried a critical RCE advisory plus two high-severity ones | A03 | Fixed (16.3.6, audit clean) |
| An invalid `sort` returned 200 while silently ignoring the request | A10 | Fixed (now 400) |
| Deleting an inventory asset orphaned its matches: `ON DELETE CASCADE` is in the schema, but SQLite does not enforce foreign keys, so the rows survived under test and would have been cleaned only in Postgres | A06 | Fixed (deleted explicitly) |
| The production database had no `alembic_version` row at all — it was built entirely by `create_schema()`, so `alembic upgrade head` would have tried to replay the baseline over an existing schema | A02 | Fixed (stamped, after verifying the schema matched a migration-built reference) |

The first two were found by attacking the running stack, not by reading the
code. Both would have shipped.

---

## Rampart: the inventory

An environment describes what a real network actually runs. It is the most
sensitive thing this system stores — every other table holds public data —
and it is treated accordingly.

**It never leaves the deployment.** No ingestion worker reads it, nothing in it
is sent to a source, and no asset name, vendor, product or version is written to
a log. The only way it leaves is the export the owner asks for, which says in
its own footer what it is.

**One door.** Every read and write goes through
`services/rampart/repository.py`, whose functions all take `owner` as their
first argument and apply it. Routers never build a statement against the Rampart
tables. The rule is mechanical rather than clever on purpose: a scoping mistake
here is not the kind of bug you get to fix after somebody notices.

**It fails closed.** `lib/authz.isRampartOwner` is deliberately *not* `isAdmin`.
`isAdmin` falls back to the whole allowlist when `AUTH_ADMIN_EMAILS` is unset —
a reasonable default for "may trigger an ingestion run", and the wrong one here.
With no `AUTH_ADMIN_EMAILS`, nobody reaches the inventory, including accounts the
rest of the dashboard treats as admins. A signed-in non-owner gets 403 from
`/api/rampart/*` and **404** from the pages: whether this deployment keeps an
inventory is itself worth not confirming.

**Writes are server-side only.** The CORS policy allows GET and POST from the
dashboard origin, so a browser cannot issue the inventory's PATCH or DELETE
cross-origin at all. The frontend mutates from Server Actions, which carry
Next's own origin check, and each action re-checks ownership: the middleware
guards the route, but an action is reachable by its own id, so "the page was
protected" is not the same as "this call was".

**Exports are escaped twice.** Markdown special characters, and the spreadsheet
formula prefixes — both reusing the controls in `services/export.py` rather than
a second copy. These matter more here than in the per-CVE export, because the
cells contain text the owner typed: an asset labelled `=cmd|'/c calc'!A1` must
not execute when the CSV is opened.

### Prerequisite: identity propagation, before a second owner exists

`api/deps.current_owner` returns a configured constant. The API has no way to
tell one caller from another — it trusts the internal network and the Next.js
middleware in front of it — so **every request maps to the same owner**.

That is fine for one operator and unacceptable for two. Today the real access
control for Rampart is the middleware, not the API; with a second owner, anyone
who reached the backend directly would read the first owner's inventory, because
the backend would have no basis on which to refuse. `owner_id` is on every table
and every query from the first migration so that the data model is ready, but
the *check* is not.

**Before a deployment has more than one environment owner**, identity must be
propagated from the frontend to FastAPI and `current_owner` must derive the
owner from the request rather than from configuration. Nothing else in the
Rampart code has to change; that function is the seam.

## Known limitations

- **Authentication lives at the edge, not in the API.** Deployed, the backend
  is only reachable from the frontend container, so anything that obtains code
  execution inside the deployment talks to the API unauthenticated. Acceptable
  for a small trusted group; not acceptable if Asber ever becomes multi-tenant,
  at which point authentication has to move into FastAPI itself.
- **Community PoC repositories are Tier 4 and unverified.** Fake and malicious
  "PoCs" are common on GitHub. The UI warns on every one. Never run them outside
  an isolated lab.
- **Heuristic ATT&CK mappings are inferences**, labelled as such — they are not
  claims made by any source.
- **Co-mention is not attribution.** When a report mentions a CVE and an actor,
  the dashboard records a low-cost association *with the evidence link*, not a
  statement of fact.
- **Two schema paths.** Deployments run Alembic migrations; the test suite and
  throwaway SQLite databases still use `create_all`. The two are checked against
  each other, but only Alembic can alter an existing table. The scheduler also
  calls `create_schema()` at startup, which means a new table appears on a
  running instance without the migration ever being applied — so a broken
  migration will not show up locally. Verify migrations against a fresh
  database, not by watching the app start. See DEPLOY.md.
- **One Rampart owner per deployment.** The API cannot distinguish callers;
  see "Prerequisite: identity propagation" above. `AUTH_ADMIN_EMAILS` must name
  exactly one account until that changes.

## Reporting a problem

This is a personal project. If you find an issue in the ingestion or
sanitisation logic, open an issue with the offending input and the observed
behaviour.
