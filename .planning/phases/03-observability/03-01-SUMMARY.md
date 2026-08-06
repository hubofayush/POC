# 03-01 SUMMARY — Observability & Ops

## Status
COMPLETE — all 6 waves. Full suite: **132 tests passing** (Phase 2 checkpoint: 113). 6 commits on main (baba3e2..ec21d54). Live smoke 13/13; probes, metrics and access logs verified against the running server.

## What Changed

### Metrics (wave 1) — 733496c
- `prometheus-client` dependency; `app/observability/metrics.py` registry
- `HttpMetricsMiddleware`: per-method/path/status request counter, latency histogram, in-flight gauge; `/metrics` excluded from its own metrics
- `GET /metrics` (Prometheus text format, not in OpenAPI schema)
- Guardrail decision counter wired into the ingress pipeline (block/pass per layer+code); D3 circuit-breaker state gauge (0/1/2) wired into the breaker transitions
- 5 tests (families present, status recording, self-exclusion, decision counter, gauge values)

### Probes (wave 2) — b58f5fd
- `GET /health/live` — process liveness
- `GET /health/ready` — DB reachability via `SELECT 1`; 503 when unavailable
- Legacy `/health` unchanged; 4 tests incl. simulated DB failure

### Proxy-aware rate limiting (wave 3) — cc0ef6d
- `TRUST_PROXY_COUNT` config; `_proxy_aware_key` uses the client IP from X-Forwarded-For (skipping the trusted hop chain); falls back to socket address when header absent/short. Trust boundary documented in code
- 6 tests (key selection for 0/1/2 proxies, fallbacks, limiter wiring)

### Docker packaging (wave 4) — da4686f
- Dockerfile: non-root `appuser` (uid 10001), no `.env` COPY (env injected via compose), stdlib-based HEALTHCHECK (no curl dependency)
- compose: DB + app healthchecks, `depends_on: condition: service_healthy`, `restart: unless-stopped`, `DB_AUTO_CREATE=false` in prod, `TRUST_PROXY_COUNT=1` behind the compose network
- **Build verification deferred — docker CLI unavailable in this environment**

### Request logging (wave 5) — ec21d54
- `RequestLogMiddleware`: `http.request` INFO events (method, path, status, latency_ms, client_ip, user_agent); `http.request.error` ERROR events for >=500 and unhandled exceptions; `/metrics` and `/health*` excluded
- 4 tests (401 logged, 200 invoke logged, probes excluded, 500 logged as error — via `raise_app_exceptions=False` client since Starlette's ServerErrorMiddleware re-raises by design)

## Verification
- `py -m pytest -q --no-header` → **132 passed**
- Live: `/health/live` + `/health/ready` 200; `/metrics` shows counters incl. all 12 guardrail decisions from the smoke run; breaker state 0.0 (closed)
- Smoke 13/13 correct on the new server (restarted post-migration)

## Notes / Follow-ups
- `/metrics` is unauthenticated by design (Prometheus scraping); protect at network level
- Docker build/run verification pending a Docker-capable machine (compose config is review-only here)
- Metrics label cardinality is bounded (fixed endpoint set); `/metrics` self-exclusion prevents scrape inflation
- Phase 0 (ruff/mypy/CI, pinning) and Phase 4 (CI gates, runbooks, Postman update) remain
