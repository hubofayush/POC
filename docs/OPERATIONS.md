# OPERATIONS

Reference for operating the D5 Security Layer: endpoints, metrics, log events,
and configuration.

## Endpoints

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| GET | `/health` | none | Legacy summary (status/version/timestamp) |
| GET | `/health/live` | none | Liveness — always 200 when the process is up |
| GET | `/health/ready` | none | Readiness — 200 if DB reachable, else 503 |
| GET | `/metrics` | none* | Prometheus metrics (protect at network level) |
| POST | `/auth/login` | none | Login, returns `access_token` + `refresh_token` (rate-limited 100/min/IP) |
| POST | `/auth/refresh` | none | Rotate refresh token (rate-limited 30/min/IP); reuse detection revokes the family |
| POST | `/invoke` | Bearer | Run the full pipeline: guardrails → PHI mask → D3 → egress filter → audit |
| GET | `/audit/entries` | Bearer (role-scoped) | Audit log, org-scoped (admin: all) |
| GET | `/audit/stats` | Bearer | Aggregates (success rate, blocked, PHI accesses, avg latency) |
| GET | `/audit/verify` | admin | Replay the hash chain; `{valid, entries_checked, first_broken_entry_id}` |
| GET | `/traces` | Bearer (org-scoped) | Persisted traces with spans |
| GET | `/traces/{id}` | Bearer (org-scoped) | Single trace |

\* `/metrics` is intentionally unauthenticated for Prometheus scraping.

## Error contract

- 401 invalid/expired token, bad credentials; 403 role/org/consent denial;
  404 unknown resource; 413 body too large; 422 guardrail block (detail.code =
  e.g. `PROMPT_INJECTION_DETECTED`); 429 rate limited; 503 D3 unavailable.
- Guardrail errors are 422 with `detail.code` + `detail.layer` (client-facing
  detail is sanitized: matched patterns/previews are stripped server-side).

## Metrics (Prometheus)

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `d5_http_requests_total` | counter | method, path, status | Request count |
| `d5_http_request_duration_seconds` | histogram | method, path | Latency (0.005–10s buckets) |
| `d5_http_inflight_requests` | gauge | — | Concurrent requests |
| `d5_guardrail_decisions_total` | counter | layer, decision, code | Guardrail outcomes (block/pass) |
| `d5_d3_circuit_state` | gauge | — | 0 closed, 1 half-open, 2 open |

`/metrics` is excluded from its own counters (no scrape inflation).

## Log events

Structured logs (structlog). Key events:

| Event | Level | Meaning |
| ----- | ----- | ------- |
| `http.request` / `http.request.error` | info/error | Access log; error for >=500 |
| `guardrail.pipeline.passed` / `guardrail.pipeline.blocked` | info/warning | Pipeline outcome with code+layer |
| `phi.detection.failed` | error | PHI engine failed (fail-open + alarm) |
| `audit.logged` | info | Audit entry written |
| `egress.d3.provider_error` / `.timeout` / `.retry` | warning/info | D3 failures with attempt counts |
| `egress.d3.circuit_opened` / `.circuit_closed` / `.circuit_reopened` | warning/info | Breaker transitions |
| `egress.d3.failed` | error | D3 exhausted → 503 returned |
| `health.ready_failed` | warning | Readiness probe DB failure |

## Configuration reference

All settings live in `app/config.py` (env-overridable, `.env` supported).

| Setting | Default | Notes |
| ------- | ------- | ----- |
| `DATABASE_URL` | sqlite+aiosqlite:///./d5_dev.db | Prod: `postgresql+asyncpg://...` |
| `DB_AUTO_CREATE` | true | Create tables at startup (dev); false in prod |
| `JWT_*` | RS256, 15min/7d | Key paths, issuer, audience |
| `AUTH_MAX_FAILED_ATTEMPTS` / `AUTH_LOCKOUT_MINUTES` | 5 / 15 | Per-account lockout |
| `AUTH_LOGIN_RATE_LIMIT` / `AUTH_REFRESH_RATE_LIMIT` | 100/min / 30/min | Per-IP (proxy-aware) |
| `TRUST_PROXY_COUNT` | 0 | Trusted proxies for X-Forwarded-For keying |
| `MAX_REQUEST_BODY_BYTES` | 65536 | Reject oversized bodies early |
| `CORS_ALLOW_ORIGINS` | "" (same-origin) | Comma-separated allowlist |
| `GUARDRAIL_TOPIC_MODE` / `GUARDRAIL_LANGUAGE_MODE` | warn | warn vs block |
| `GUARDRAIL_MAX_INPUT_BYTES` | 32768 | L1 input budget |
| `GUARDRAIL_ENCODED_PAYLOAD_BLOCK` | true | L2 base64/hex blocking |
| `GUARDRAIL_CONSENT_DEFAULT_GRANTED` | false | Default-deny consent |
| `LLM_GUARDRAIL_ENABLED` / `PROVIDER` / `MODEL` / `MODE` | true / gemini / gemini-3.1-flash-lite / block | L5 evaluator |
| `LLM_GUARDRAIL_TIMEOUT_SEC` | 2.0 | L5 ceiling |
| `PRESIDIO_ENABLED` / `PRESIDIO_MIN_SCORE` / `PRESIDIO_ANONYMIZER_MODE` | true / 0.6 / replace | PHI engine |
| `D3_TIMEOUT_SEC` | 5.0 | Per-attempt D3 timeout |
| `D3_MAX_RETRIES` | 2 | Backoff retries (base 0.25s, doubles) |
| `D3_CIRCUIT_FAILURE_THRESHOLD` / `D3_CIRCUIT_RESET_SEC` | 5 / 30.0 | Breaker parameters |

## Design limits (known)

- Audit chain lock and circuit breaker are single-process; distributed
  deployments need a Postgres advisory lock and a shared breaker store
- Traces/spans are stored as JSON on the trace row (POC scale)
- `/metrics` unauthenticated — protect with network policy/ingress rules
