# 02-01 SUMMARY — Reliability

## Status
COMPLETE — all 5 tasks + integration verified. Full suite: **113 tests passing** (Phase 1 checkpoint: 97). 7 commits on main (863441e..4b45089). Live smoke 13/13 correct; `/audit/verify` valid over migrated data; traces persisted.

## What Changed

### 1.1 Test DB isolation — 3f01793
- Tests run against dedicated `d5_test.db` (env set in conftest before app import); session fixture wipes it. Test runs no longer touch the dev server's data.

### 1.2 Alembic migration 02 — 7e0a05c (`67837e0c5670`)
- `audit_log.prev_hash` (String(64), server_default '') + `traces` table (JSON metadata/spans) + indexes
- Backfills chained hashes for pre-existing rows using the canonical UTC timestamp format
- Upgrade (with data), downgrade verified on scratch DB; dev DB migrated live (stamp baseline → upgrade head)

### 2 Audit hash chaining — 586b624
- Every entry hashes `prev_hash|id|user|action|status|canonical_ts|details`; a tamper anywhere breaks the rest of the chain
- Inserts serialized by an asyncio lock (single-process; Postgres advisory lock noted for distributed)
- `verify_chain()` + `GET /audit/verify` (admin only) replay the log and report the first broken entry
- Fixed two latent bugs: hashes were computed over `entry_id=None` and over naive-vs-aware timestamps (SQLite round-trip)
- 5 tests incl. tamper detection via raw SQL

### 3 Trace persistence — e25f7f8
- `TraceRepository` + `Trace` model; spans stored as JSON, updated in place by span_id
- `Tracer` is now an async facade over the store; invoke service + `/traces` API await it; blocked requests persist `status="blocked"`
- 4 API tests + 3 reworked unit tests

### 4 Async offload — 2c7d48f
- argon2 verify/dummy_verify on `/auth/login` and PHI masking (regex+Presidio) in invoke service now run via `asyncio.to_thread` — no CPU-bound work on the event loop

### 5 Egress hardening — 4b45089
- `D3Client`: injectable async provider (mock default), per-attempt timeout (`asyncio.wait_for`), exponential-backoff retries on retryable failures, circuit breaker (closed/open/half-open probe) with structured logs
- invoke service: D3 failure → trace `failed`, audit entry `D3_UNAVAILABLE` (status=block), **HTTP 503** instead of raw 500
- Config: D3_TIMEOUT_SEC, D3_MAX_RETRIES, D3_RETRY_BASE_DELAY_SEC, D3_CIRCUIT_FAILURE_THRESHOLD, D3_CIRCUIT_RESET_SEC (+ .env.example)
- 7 tests: retry-then-success, exhausted retries, non-retryable no-retry, timeout retried, breaker opens + short-circuits, half-open recovery, API 503

## Verification
- `py -m pytest -q --no-header` → **113 passed**
- Migration 02 upgrade/downgrade on scratch DB; dev DB migrated (stamp + upgrade)
- Live smoke 13/13; `/audit/verify` valid=True over 13 entries (backfill + runtime chain interop); `/traces` returns persisted org-scoped traces
- Dev server restarted on new code (old server was pre-migration)

## Notes / Follow-ups
- Chain locking is single-process; distributed deployments need a Postgres advisory lock or sequence-based prev_hash
- Span storage is JSON-on-row (POC scale); normalize to a span table if volume grows; `end_span` does a bounded recent-trace scan
- Per-IP rate limits still POC-grade (proxy-aware keying is Phase 3)
- ruff/mypy/CI, dependency pinning (Phase 0) still open; Postgres runtime + docker compose (Phase 3)
