# DEPLOYMENT

Production deployment guide for the D5 Security Layer.

## Architecture

Single-host Docker Compose deployment:

```
Reverse proxy (TLS)  -->  app (python:3.12-slim, non-root uid 10001)  -->  postgres:16-alpine
                             ^ healthcheck (/health/live)                    ^ healthcheck (pg_isready)
                             | auto-migrates on start (alembic upgrade head)
```

- App container starts with `alembic upgrade head && uvicorn ...` — migrations apply automatically on every start.
- `DB_AUTO_CREATE=false` in compose — tables come only from migrations.
- `TRUST_PROXY_COUNT=1` — the reverse proxy is the single trusted hop; rate limits key on the real client IP.
- No `.env` file is baked into the image; all secrets are injected at runtime.
- `keys/` is mounted read-write from the host so key rotation never requires an image rebuild.

## Prerequisites

- Docker Engine + Compose v2 on the host
- A TLS-terminating reverse proxy in front (nginx, Caddy, or a managed LB) — TLS is NOT handled by the app
- DNS name for the proxy, valid TLS cert

## First deployment

```bash
# 1. Clone + configure
git clone <repo> && cd POC
cp .env.example .env
#   -> set POSTGRES_PASSWORD to a strong URL-safe value (no @ : / chars):
#      openssl rand -base64 24 | tr -d '/+='
#   -> review ALL settings: JWT paths, DEBUG=false, LOG_LEVEL, guardrail modes,
#      LLM_GUARDRAIL_API_KEY if Layer 5 uses the Gemini API, CORS_ALLOW_ORIGINS

# 2. Provision RS256 keys on the host (mounted into the container)
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem

# 3. Build + start (db starts first; app waits for db health)
docker compose up -d --build

# 4. Verify
docker compose ps            # both services healthy
curl https://<host>/health/live    # {"status":"alive",...}
curl https://<host>/health/ready   # 200 when DB reachable
docker compose logs app | tail     # "Application startup complete"

# 5. Seed demo users (admin_01/hr_01/clinician_01, pass123) — optional
docker compose exec app python scripts/seed_users.py --demo
# Bootstrap your real admin from .env (BOOTSTRAP_ADMIN_*):
docker compose exec app python scripts/seed_users.py
```

## Operations

### Migrations
- Auto-applied on container start (`alembic upgrade head`).
- Inspect current state: `docker compose exec app alembic current`
- Manual upgrade (e.g. after a rollback): `docker compose exec app alembic upgrade head`
- **Downgrades**: not supported — the schema is append-only by design (audit chain + traces). To revert, redeploy the previous image and restore the backup.

### Backups (Postgres)
```bash
docker compose exec -T db pg_dump -U d5 -d d5 > d5_backup_$(date +%F).sql
```
Restore:
```bash
docker compose exec -T db psql -U d5 -d d5 < d5_backup_2026-08-06.sql
```
Note: restoring into a running system after the restore point breaks the audit hash chain
(`/audit/verify` will report invalid). Restore only to the exact point-in-time snapshot,
then re-verify: `curl -H "Authorization: Bearer $TOKEN" https://<host>/audit/verify`.

### Upgrades
```bash
git pull && docker compose up -d --build
# migrations run automatically; verify /health/ready + /audit/verify after
```
Single-instance assumption: if you ever scale replicas, run migrations once manually
(`docker compose run --rm app alembic upgrade head`) before scaling, or use a
migration-sidecar job — concurrent `upgrade head` from N replicas can race.

### Key rotation
1. Generate a new keypair into `keys/` (private.pem, public.pem) on the host
2. `docker compose restart app` — tokens signed with the old key fail at next
   refresh (`Invalid token`); users re-login. Plan a maintenance window.

## Hardening checklist

- [ ] `POSTGRES_PASSWORD` from `.env`, never committed; app has no DB password in code
- [ ] `DEBUG=false`, `LOG_LEVEL=INFO`, `DEV=false` (JSON logs) in prod
- [ ] `DB_AUTO_CREATE=false` (set by compose); migrations only
- [ ] Non-root app user (uid 10001), keys 0600 on host, `.env` not copied into image
- [ ] TLS terminated at reverse proxy; `TRUST_PROXY_COUNT=1` matches the proxy chain exactly
- [ ] `GUARDRAIL_CONSENT_DEFAULT_GRANTED=false` (default-deny consent)
- [ ] `/metrics` and `/health*` reachable only from the proxy/network, not the public internet
- [ ] `CORS_ALLOW_ORIGINS` set to the real frontend origin
- [ ] Periodic `GET /audit/verify` job (cron) with alert on `valid=false`
- [ ] `POSTGRES_PASSWORD` and JWT keys excluded from shell history/backups of the repo
