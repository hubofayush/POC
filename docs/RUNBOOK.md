# RUNBOOK

Operational playbook for the D5 Security Layer.

## First-time setup

```bash
# Python env
py -m venv .venv && .venv\Scripts\activate      # Windows
pip install -e ".[dev]"

# Keys (RS256 JWT)
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Config
copy .env.example .env                          # dev defaults (SQLite) are fine

# Seed users (admin_01/comp_01/clinician_01, password pass123)
py scripts/seed_users.py

# Run
py -m uvicorn app.main:app --reload --port 8000
```

## Migrations

```bash
# Create (after model changes)
py -m alembic revision --autogenerate -m "describe change"

# Apply to dev DB (server must be stopped on Windows — SQLite file lock)
py -m alembic upgrade head

# Show state / downgrade one
py -m alembic current
py -m alembic downgrade -1
```

> Dev SQLite DBs created by `create_tables` (DB_AUTO_CREATE=true) have no
> alembic_version table. If `upgrade head` fails with "table already exists",
> stamp the baseline first: `py -m alembic stamp <baseline-rev>`, then upgrade.

## Deploy (Docker Compose, Postgres)

```bash
docker compose up -d --build
# app -> http://localhost:8000, postgres -> localhost:5432 (d5/d5_secret)
docker compose ps                              # both healthy
docker compose logs -f app
```

Compose runs `alembic upgrade head` before starting uvicorn; DB health is
gated with `depends_on: condition: service_healthy`.

## Upgrades

1. `git pull` / deploy new image
2. Verify `/health/ready` returns 200 (DB migrated) — the app runs
   `alembic upgrade head` on boot in Docker
3. Check `/metrics` for `d5_http_requests_total` and guardrail counters
4. Run `py scripts/smoke_test.py` against the instance (13 scenarios)

## Backup / restore

- **SQLite (dev)**: copy `d5_dev.db` while the server is stopped
- **Postgres (compose)**: `docker compose exec db pg_dump -U d5 d5 > d5.sql`;
  restore with `docker compose exec -T db psql -U d5 d5 < d5.sql`
- Migrations are idempotent-ish: never restore a dump across schema versions
  without running `alembic upgrade head` afterwards

## Monitoring

- `GET /health/live` — process liveness (used by Docker HEALTHCHECK)
- `GET /health/ready` — DB reachability; 503 while unavailable
- `GET /metrics` — Prometheus; catalog in docs/OPERATIONS.md
- Access log: `http.request` INFO events; `http.request.error` for >=500

## Troubleshooting

| Symptom | Cause / fix |
| ------- | ----------- |
| Port 8000 already in use on Windows | uvicorn `--reload` spawns a child that survives parent kill. `netstat -ano \| findstr :8000`, `taskkill //PID <pid> //F` (repeat for child PID) |
| `no such column: audit_log.prev_hash` after restart | Dev DB not migrated. Stop server, `py -m alembic upgrade head` (stamp baseline first if needed), restart |
| Rate-limit 429s in dev | Defaults are 100/min login, 30/min refresh. Fine for smoke; raise via `AUTH_LOGIN_RATE_LIMIT`/`AUTH_REFRESH_RATE_LIMIT` |
| `D3_UNAVAILABLE` 503s | Downstream mock client failing or breaker open. Check `egress.d3.*` logs and `d5_d3_circuit_state` gauge (2=open); breaker resets after `D3_CIRCUIT_RESET_SEC` (30s) |
| `presidio.unavailable` warning | presidio/spacy not installed in this env; PHI detection falls back to regex + fail-open alarm logs. Install with `pip install presidio-analyzer presidio-anonymizer spacy` + `py -m spacy download en_core_web_lg` |
| Login slow (~100ms+) | argon2 verify is CPU-bound by design (see AUTH docs); runs off the event loop |
| `audit/verify` reports broken chain | Data tampered or migration backfill mismatch; investigate the first broken entry id |
| Test run touches dev DB | Tests are isolated to `d5_test.db` (see tests/conftest.py); delete it to force a clean slate |
