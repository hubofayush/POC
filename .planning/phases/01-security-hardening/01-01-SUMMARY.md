# 01-01 SUMMARY — Security Hardening

## Status
COMPLETE — all 8 implementation tasks + integration verified. Full suite: **97 tests passing** (baseline was 68). 9 commits on main (dadbfa9..1f86aa7). Smoke test 13/13 scenarios correct against the running dev server.

## What Changed

### 1.1 Real user store (auth rework) — commits 46d65fd, 7e425dc
- `users` + `refresh_tokens` tables via alembic baseline migration `581448aea3b8` (up/down verified; `migrations/script.py.mako` added)
- Passwords hashed with **argon2id** (pwdlib); `dummy_verify` defeats username enumeration timing
- Login now takes `{"username","password"}`; JWT sub = username; claims carry **iss/aud/jti**
- Refresh tokens hashed at rest (SHA-256), **rotation + reuse detection** revokes the whole family
- Failed-attempt **lockout** (5 tries / 15 min, configurable) on top of per-IP rate limits
- `scripts/seed_users.py` bootstrap admin; `ensure_demo_users()` seeds 4 demo users (admin_01, comp_01, hr_01, clinician_01 — org_uma)
- Old mock auth API removed (MOCK_USERS, query-param refresh) — breaking change accepted

### 1.2 Org isolation end-to-end — a46e72d
- `require_org_scope()` in RBAC: admin → all orgs, everyone else restricted to token org
- `/audit/logs` and stats org-scoped for non-admins; `/traces` filtered; foreign-org trace → 404
- `/invoke` rejects context org mismatches; traces tagged with user org

### 1.3 CORS allowlist — 69d83da
- Middleware only registered when `CORS_ALLOW_ORIGINS` non-empty; never `*` with credentials

### 1.4 LLM guard API security — 6abd082
- API key moved from URL query to **`x-goog-api-key` header**
- Only `gemini` provider has an HTTP integration; other providers log a warning and use the local zero-shot engine (broken openai branch removed)
- Evaluator JSON validated by pydantic `_EvaluatorVerdict`; malformed/invalid/error responses fall back safely
- Fixed latent `str.format` KeyError from unescaped JSON example in the system prompt (would have crashed every real Gemini call)

### 1.5 Response sanitization — 0db248c
- Client-facing 422/403 bodies strip internal details (`matched_pattern`, `decoded_preview`, `encoding`, `key_path`), string values capped at 200 chars; full details remain in audit log

### 1.6 Body cap + rate limits — 414dc1d
- `BodySizeLimitMiddleware`: 413 for bodies > `MAX_REQUEST_BODY_BYTES` (64 KB), incl. chunked
- Per-IP slowapi limits on `/auth/login` (100/min) and `/auth/refresh` (30/min), configurable

### 1.7 PHI fail-open + alarm — e75adca
- Presidio analyze + detector tier-2 failures now emit **`phi.detection.failed`** structured alarm (fail_mode=fail_open, layer, error_class) — traffic continues but monitoring must alert; no more silent downgrade

### 1.8 Consent default-deny — 597b167
- `GUARDRAIL_CONSENT_DEFAULT_GRANTED=false` (prod default): absent `consent_granted` → denied; explicit `true` passes; explicit `false` always blocked

### Integration (Wave 2)
- Smoke/demo scripts updated to new auth contract; smoke verified 13/13 scenarios live

## Verification
- `py -m pytest -q --no-header` → **97 passed** (baseline 68)
- `py scripts/smoke_test.py` against dev server (port 8000) → all PASS/BLOCK scenarios as expected, traces API OK
- New tests: 15 auth (rotation, reuse, lockout, claims), 5 org isolation, 5 LLM guard routing, 3 response sanitization, 2 body/rate, 2 PHI alarm, consent flips

## Notes / Follow-ups
- Dev server runs without GEMINI_API_KEY → live L5 path is local fallback; real API path covered by FakeGeminiClient tests
- Per-IP rate limits are POC-grade (no proxy awareness); Phase 3 adds trusted-proxy keying
- Postman collection still uses the old auth contract — Phase 4 scope
- ruff/mypy/CI, docker compose, real Postgres migrations — Phases 0/2/3 scope
