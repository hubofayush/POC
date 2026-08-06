# D5 Security Layer

A production-oriented security gateway that protects healthcare/compliance AI
calls to a downstream model service (D3). It enforces a 5-layer ingress
guardrail pipeline, PII/PHI detection and masking (Presidio), RBAC with tenant
isolation, a tamper-evident audit trail, persisted traces, and hardened egress
(timeout / retry / circuit breaker).

## Features

- **5-layer ingress guardrails**: schema/UTF-8 budget (L1), prompt injection /
  encoded payloads (L2), consent + RBAC policy (L3), content sanity (L4), LLM
  safety evaluator (L5, Gemini or local fallback)
- **PHI masking**: regex + Presidio NLP; fail-open with explicit alarm logs
- **Auth**: RS256 JWT, argon2id passwords, refresh-token rotation with reuse
  detection, per-account lockout, per-IP rate limits
- **Audit**: tamper-evident SHA-256 hash chain, `GET /audit/verify` to check it
- **Tracing**: persisted traces/spans, org-scoped `GET /traces`
- **Observability**: Prometheus `/metrics`, `/health/live` + `/health/ready`
  probes, structured access logging
- **Ops**: hardened Dockerfile (non-root), docker-compose with Postgres 16

## Quickstart (local dev)

```bash
# 1. Environment (Python 3.12 recommended; 3.14 works)
py -m venv .venv && .venv\Scripts\activate   # Windows
pip install -e ".[dev]"

# 2. RSA keys for JWT (RS256)
py scripts/gen_keys.py                       # or openssl genrsa/rsa -pubout into keys/

# 3. Configure
copy .env.example .env                       # defaults work for dev (SQLite)

# 4. Run
py -m uvicorn app.main:app --reload --port 8000
#   -> http://localhost:8000/docs   (OpenAPI)

# 5. Seed demo users, smoke test
py scripts/seed_users.py
py scripts/smoke_test.py
```

## Tests & quality gates

```bash
py -m pytest -q --no-header          # 132 tests, isolated d5_test.db
py -m ruff check app/ tests/ scripts/
py -m mypy app/ tests/
```

CI (`.github/workflows/ci.yml`) runs ruff + mypy + pytest + an `alembic
upgrade head` verification on every push/PR.

## Project layout

```
app/
  api/v1/          FastAPI routers (auth, invoke, audit, traces)
  core/            guardrails (5 layers), phi, security, tracing, audit, logging
  integrations/    d3_client (timeout/retry/circuit breaker, mock provider)
  middleware/      body limit, error handler, metrics, request log, rate limit
  models/          SQLAlchemy models + engine
  repositories/    data access (auth, audit, traces)
  observability/   Prometheus registry
  services/        ingress pipeline, invoke orchestration, egress filtering
  schemas/         Pydantic request/response models
migrations/        Alembic revisions (2: baseline, reliability)
scripts/           seed_users, smoke_test, guardrails_demo
tests/             pytest suite (132 tests)
docs/              RUNBOOK.md, OPERATIONS.md
postman/           postman_collection.json
```

## Production notes

- Postgres: set `DATABASE_URL=postgresql+asyncpg://...` and
  `DB_AUTO_CREATE=false`; apply schema with `alembic upgrade head`
- Deploy: `docker compose up -d` (Postgres + app with healthchecks)
- Rate limits key on the real client IP when `TRUST_PROXY_COUNT>0` — only
  enable behind a trusted proxy
- See `docs/RUNBOOK.md` (ops/troubleshooting) and `docs/OPERATIONS.md`
  (endpoints, metrics, config reference)
