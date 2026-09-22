# Asber

> **AS**sistir (to watch) + cy**BER** — a watchtower for cyber threats.

A local, personal threat-intelligence centre. It collects from public, official
sources, **normalises** the data into one model, **correlates** related entities
and presents a SOC-style dashboard built to answer, quickly:

1. What is new?
2. Which vulnerabilities are being actively exploited?
3. Which CVEs have a public PoC or exploit?
4. Which vulnerabilities actually matter to me?
5. Which threat actors and campaigns are active?
6. Which MITRE ATT&CK techniques keep showing up?
7. Which malware is being observed?
8. What new offensive research was published?
9. Which sources are talking about the same threat?
10. How can a threat be investigated and detected?

It is **not** a news aggregator: every CVE becomes one canonical entity that all
sources attach to, with an explainable priority score and a full source trail.

---

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
```

Then open **http://localhost:3000**.

Both services bind to `127.0.0.1` and there is no authentication: on a
personal machine the operating system is the access control. To run Asber on a
server, follow [DEPLOY.md](DEPLOY.md) — it adds sign-in, TLS and migrations.

No API key is required. The first collection cycle starts immediately:

| Stage | What happens | Typical time |
|---|---|---|
| MITRE ATT&CK import | ~55 MB STIX bundle → local knowledge base | 1–3 min |
| CISA KEV | full catalog (~1,700 exploited CVEs) | seconds |
| RSS feeds | Unit 42, Talos, BleepingComputer, Krebs, The Record | seconds |
| Exploit-DB | ~46,000 exploit records | 1–2 min |
| NVD | last 14 days of changes, then enrichment | 10–40 min (rate limited) |
| GitHub | PoC search for the highest-priority CVEs | a few minutes |

Watch progress at **http://localhost:3000/sources** or:

```bash
docker compose logs -f scheduler
```

The dashboard is usable within ~2 minutes (KEV + feeds land first); NVD detail
fills in progressively.

### Useful commands

```bash
docker compose ps
```

```bash
docker compose logs -f scheduler backend
```

```bash
docker compose down
```

To wipe the database and start over:

```bash
docker compose down -v
```

---

### Quick trial without PostgreSQL

The backend also runs on SQLite, which is handy for a first look (and is what
the test suite uses). PostgreSQL full-text search is the only feature that
degrades — search falls back to `LIKE`.

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
cd backend && DATABASE_URL="sqlite:///./local.db" .venv/bin/python -m scripts.collect_once cisa_kev mitre_attack unit42 talos bleepingcomputer krebs therecord
```

```bash
cd backend && DATABASE_URL="sqlite:///./local.db" .venv/bin/python -m uvicorn app.main:app --port 8000
```

```bash
cd frontend && npm install && API_INTERNAL_URL=http://127.0.0.1:8000 npm run dev
```

`scripts/collect_once.py` runs any set of sources once (`--all` for every
implemented one) without waiting for the scheduler.

## Running without Docker

Backend (needs PostgreSQL 16 and, optionally, Redis):

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
DATABASE_URL=postgresql+psycopg://asber:asber@localhost:5432/asber .venv/bin/uvicorn app.main:app --reload
```

```bash
DATABASE_URL=postgresql+psycopg://asber:asber@localhost:5432/asber .venv/bin/python -m app.scheduler
```

Frontend:

```bash
cd frontend && npm install && API_INTERNAL_URL=http://localhost:8000 npm run dev
```

Tests (no network access needed — everything runs against local fixtures):

```bash
cd backend && .venv/bin/python -m pytest -q
```

---

## What the dashboard gives you

**Threat Overview** — cards for the chosen window (24h / 7d / 30d / 90d):
actively exploited, added to KEV, new CVEs, new exploits, new PoCs, threat
actors / malware / campaigns seen, new research, news, detection repositories.

**Threats** — the working table: severity, CVE, vendor/product, signals
(KEV / exploited / exploit / PoC), impact tags, ATT&CK techniques, number of
independent sources, latest activity and the Threat Relevance score. Filterable
by window, exploitation state, impact (RCE / priv-esc / auth bypass), platform
(Windows, Linux, cloud, Active Directory, identity, web, network), vendor,
product, threat actor and technique.

**CVE page** — overview, risk with the full score breakdown, CISA KEV block,
exploitation evidence, public exploits and PoCs, threat actors / campaigns /
malware (with the report each association came from), ATT&CK techniques with
detection strategies, analytics and log sources, affected products, a visual
timeline, research, news, and a source table with tier, publication and
collection dates. Exportable as **Markdown, JSON or CSV**.

**MITRE ATT&CK** — the Enterprise matrix, with techniques highlighted by how
often they appear in the reports you actually collected. Every entity page shows
its relationships, the reports that mention it and the CVEs co-mentioned with it.

**Source Health** — per source: status, last successful sync, last attempt,
items, latency and last error. If the dashboard is stale, this page says so, and
the overview shows a warning banner.

---

## Threat Relevance Score

A transparent 0–100 prioritisation score — **not** a CVSS replacement. Each
factor that fires is shown with its points and the reason:

```
Threat Relevance: 87
  +25  CISA KEV                     Listed in the CISA KEV catalog
  +15  Active exploitation          Reported by: CISA KEV, Unit 42
  +12  Public exploit               1 public exploit (Exploit-DB)
  +10  Ransomware association       Known use in ransomware campaigns
   +9  CVSS severity                CVSS base score 9.8
   +8  Public PoC                   1 public PoC repo (unverified)
   +8  Threat actor association     Mentioned alongside: APT28
   +8  Remote code execution        Impact classified as RCE
   +8  Recency                      New activity 1 day ago
   +7  Authentication bypass        …
   +6  Internet-facing product      …
```

Weights live in one table (`backend/app/services/scoring.py`) and are shown in
the UI under **Settings**.

---

## Sources

22 sources are registered; 8 workers are implemented in Phase 1. Every endpoint
was verified before being registered — see **[SOURCES.md](SOURCES.md)** for the
per-source contract (API/feed used, authentication, rate limit, polling
interval, fields collected, deduplication strategy, failure behaviour).

Collection rules, applied everywhere:

- official API → RSS/Atom → STIX/TAXII → public JSON → official repository →
  sitemap → HTML scraping only as a last resort (not needed by any current source)
- `robots.txt`, terms of service and rate limits are respected
- conditional requests (ETag / Last-Modified) so unchanged feeds are not re-downloaded
- no CAPTCHA, paywall, authentication or anti-bot mechanism is ever bypassed
- only titles, short excerpts and metadata are stored — never full article copies

---

## Documentation

| File | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | components, ingestion pipeline, correlation, scheduling |
| [SOURCES.md](SOURCES.md) | the source registry, per-source contract, verification results |
| [DATABASE.md](DATABASE.md) | schema, every table and column, query patterns |
| [SECURITY.md](SECURITY.md) | threat model and the safety rules this project enforces |
| [DEPLOY.md](DEPLOY.md) | running Asber on a server: authentication, TLS, migrations, backups |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to add a source, run tests, code conventions |
| [.env.example](.env.example) | every configuration option, all optional |

---

## Roadmap

**Phase 1 — done.** CISA KEV, NVD (+SSVC), MITRE ATT&CK, Exploit-DB, GitHub,
Unit 42, Talos, BleepingComputer, Krebs, The Record; dashboard, search, filters,
CVE detail page, timeline, source health, exports, scheduled ingestion.

**Phase 2.** MSRC (CVRF), Mandiant, SentinelLabs, CrowdStrike, Qualys, Project
Zero, SigmaHQ, YARA, OTX, MalwareBazaar, URLhaus, VirusTotal lookups. These
sources are already registered, documented and visible on the Source Health
page — their workers are what is missing. The feed-based ones only need
`SOURCES_ENABLED=msrc,mandiant,sentinellabs,crowdstrike,qualys,project_zero`.

**Phase 3.** Threat graph, watchlists with alerts, notification centre, daily
briefing, optional AI summaries (every sentence traceable to a collected source).

---

## Safety

This is an **analysis** tool. It never executes a PoC or exploit, never
downloads malware samples, never runs external code, and never sends your files
anywhere. See [SECURITY.md](SECURITY.md).
