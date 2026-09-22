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
- The API and the dashboard bind to `127.0.0.1` only. This application has **no
  authentication** and is not designed to be exposed to a network. If you need
  remote access, put it behind a reverse proxy with authentication and TLS.
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

## Known limitations

- **No authentication or multi-user support.** Single-user, local, by design.
- **Community PoC repositories are Tier 4 and unverified.** Fake and malicious
  "PoCs" are common on GitHub. The UI warns on every one. Never run them outside
  an isolated lab.
- **Heuristic ATT&CK mappings are inferences**, labelled as such — they are not
  claims made by any source.
- **Co-mention is not attribution.** When a report mentions a CVE and an actor,
  the dashboard records a low-cost association *with the evidence link*, not a
  statement of fact.
- `create_all` (no migrations yet) means a schema change requires a database
  reset in Phase 1.

## Reporting a problem

This is a personal project. If you find an issue in the ingestion or
sanitisation logic, open an issue with the offending input and the observed
behaviour.
