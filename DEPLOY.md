# Deploying Asber

The local stack in [README.md](README.md) binds everything to `127.0.0.1` and has
no authentication, because on a laptop the operating system is the access
control. Putting the same stack on a public address removes that assumption, so
the deployed configuration is a different one.

This document covers a **single-VPS deployment for a small, named group of
people**. Anything open to the public needs decisions this file does not make —
see *Not covered* at the end.

---

## What changes, and why

| | Local (`docker-compose.yml`) | Deployed (`docker-compose.prod.yml`) |
|---|---|---|
| Who can reach the backend | localhost only | nothing — it has no published port |
| Who can reach the frontend | localhost only | Caddy, which terminates TLS |
| Authentication | none needed | OAuth + an explicit e-mail allowlist |
| Schema changes | `docker compose down -v` and recollect | `alembic upgrade head` |
| Database password | default | required, no fallback |
| Rate-limit identity | peer address | real client, via a trusted proxy header |

Two of these deserve the reasoning spelled out.

**The backend is not published at all.** In production the only process bound to
a public port is Caddy. The API is reachable solely from the frontend container,
over the Compose network, which is why authentication can live in one place
(Next.js middleware) instead of on every FastAPI route.

The cost of that choice: **anything that obtains execution inside the VPS talks
to the API unauthenticated.** For a small trusted group this is a reasonable
trade against adding token verification to every endpoint. It stops being
reasonable if Asber ever becomes genuinely multi-tenant, at which point
authentication has to move into the backend.

**An empty allowlist denies everyone.** OAuth answers *who is this*, never
*may they use this*. "Sign in with Google" and nothing else means every Google
account is a valid login. `AUTH_ALLOWED_EMAILS` is that missing half, and it
fails closed on purpose.

---

## Requirements

* A host with 2 vCPU and 4 GB RAM. The stack idles at roughly 2 GB; the full
  database (Exploit-DB, MITRE ATT&CK, and `NVD_TRACK_DAYS` of NVD) lands
  between 1 and 3 GB, so 40 GB of disk is ample.
* Docker Engine with the Compose plugin.
* A domain name with an `A` record already pointing at the host — Caddy cannot
  obtain a certificate before DNS resolves.
* Ports 80 and 443 open.

## Steps

**1. Clone and configure**

```bash
git clone <your-repo> /srv/asber && cd /srv/asber
cp .env.example .env
```

Edit `.env` and set, at minimum:

```bash
ASBER_DOMAIN=asber.example.com
POSTGRES_PASSWORD=$(openssl rand -base64 32)
AUTH_SECRET=$(openssl rand -base64 32)
AUTH_ALLOWED_EMAILS=you@example.com
```

**2. Register an OAuth application** (at least one)

| Provider | Where | Redirect / callback URL |
|---|---|---|
| Google | [console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials) | `https://<ASBER_DOMAIN>/api/auth/callback/google` |
| GitHub | [github.com/settings/developers](https://github.com/settings/developers) | `https://<ASBER_DOMAIN>/api/auth/callback/github` |

Put the client ID and secret into `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET` (or
the GitHub pair). Only configured providers appear on the sign-in page.

**3. Start**

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

The backend runs `alembic upgrade head` before it starts serving, so the first
boot creates the schema and later boots are no-ops.

**4. Verify** — and check the negative case, not just the happy path:

```bash
curl -sI https://$ASBER_DOMAIN/            # 307 to /login when signed out
curl -s  https://$ASBER_DOMAIN/api/health  # {"detail":"authentication required"}
```

A JSON health response there would mean the middleware is not covering `/api`,
which would leave the whole API open. It should be a 401.

**5. Schedule backups**

```bash
crontab -e
# 0 4 * * *  cd /srv/asber && ./scripts/backup.sh >> /var/log/asber-backup.log 2>&1
```

Restore with:

```bash
gunzip -c backups/asber-<stamp>.sql.gz \
  | docker compose -f docker-compose.prod.yml exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

A backup that has never been restored is a hypothesis. Test one.

---

## Adding someone

Append their address to `AUTH_ALLOWED_EMAILS` in `.env`, then:

```bash
docker compose -f docker-compose.prod.yml up -d frontend
```

They get a read-only dashboard. `AUTH_ADMIN_EMAILS` additionally permits
triggering ingestion runs — worth keeping narrow, since those runs spend the
shared NVD and GitHub rate-limit budget.

Removing someone is the same edit in reverse, but their session cookie stays
valid for up to 7 days. To cut access immediately, rotate `AUTH_SECRET`, which
invalidates every session including your own.

## Schema changes

Migrations live in `backend/alembic/versions`. After changing `app/models.py`:

```bash
cd backend && DATABASE_URL=<url> alembic revision --autogenerate -m "what changed"
```

Read the generated file before committing it — autogenerate does not detect
every change (renames arrive as drop + add, which loses the data in that
column).

`create_schema()` still exists for tests and throwaway SQLite databases. It uses
`create_all`, which **only creates missing tables and never alters an existing
one** — on a deployed database it would appear to succeed while leaving the
schema stale. Deployments use Alembic.

Adopting migrations on a database built by the old `create_all` path:

```bash
docker compose -f docker-compose.prod.yml exec backend alembic stamp head
```

## Updating

```bash
git pull && docker compose -f docker-compose.prod.yml up -d --build
```

Take a backup first when the release contains a migration.

---

## Not covered

* **Public access.** The stack assumes every user is on the allowlist.
  Opening it up raises questions this setup does not answer: redistribution
  terms of the sources in [SOURCES.md](SOURCES.md), abuse handling, and the
  consequences of strangers relying on a dashboard's freshness.
* **Redundancy.** One host, one database. A failure means downtime and a
  restore from the most recent dump.
* **Secrets management.** Credentials live in `.env` on the host. That is the
  weakest link here; a secrets manager is the upgrade path.
