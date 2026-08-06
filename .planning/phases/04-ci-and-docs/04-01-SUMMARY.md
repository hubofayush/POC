# 04-01 SUMMARY — CI Gates & Docs

## Status
COMPLETE — all 6 waves. Quality gates green: **ruff clean**, **mypy clean (app/)**, **132 tests passing**. 4 commits on main (9c24ed9, db76497, cb68be6). CI workflow present and yaml-validated (local only — no runner here). Live smoke 13/13 + probes/metrics verified against a freshly restarted server.

## What Changed

### Wave 1 — Static quality gates (ruff + mypy)
- `ruff 0.16.1` + `mypy 2.3.0` installed and added to `[project.optional-dependencies].dev`
- `[tool.ruff]`: target py312, line-length 100, curated rule set + documented ignores (B008, BLE001, B017, TRY004, ASYNC221, ambiguous-unicode, SIM102…); per-file-ignore E402 for `app/main.py` (routers after app construction) and `tests/conftest.py` (env before imports)
- Initial run: 155 errors → auto-fix + manual: `raise ... from None` (B904) in auth; `is_(True)` (E712) + success-rate division fix in audit_repository; `all(...)` (SIM110) in ingress `check_injection`; `suppress(OSError)` (SIM105) + import order in conftest; `raise ... from exc` in readiness probe
- mypy: 5 errors → `AsyncGenerator[AsyncSession, None]` on `get_db`; `locked_until` local (non-None check before comparison); `len(list(registry.recognizers))`; one `# type: ignore[return-value]` in metrics test
- Result: `ruff check` clean, `mypy` clean, suite stays 132

### Wave 2 — CI workflow + lockfile — 9c24ed9
- `.github/workflows/ci.yml`: ubuntu-latest, Python 3.12, `requirements.lock` + `pip install -e ".[dev]"`, then ruff → mypy → pytest, then `alembic upgrade head` + `alembic current` against an isolated CI SQLite DB (`ci_mig.db`) to prove migrations apply head-to-tail
- `requirements.lock` (233 pinned lines from `pip freeze`: fastapi 0.139.2, uvicorn 0.51.0, ruff 0.16.1, mypy 2.3.0, pytest 9.1.1, prometheus_client 0.26.0…)

### Wave 3 — Docs — db76497
- `README.md`: features, quickstart (openssl keygen, not the nonexistent script), quality gates, project layout, production notes
- `docs/RUNBOOK.md`: setup, migrations (stamp-baseline-first tip), compose deploy, upgrades, backup/restore, troubleshooting table (port zombie, stale DB, 429s, breaker, presidio fallback…)
- `docs/OPERATIONS.md`: endpoint reference, error contract, metric catalog, log event catalog, config reference, design limits

### Wave 4 — Dev tooling sync — cb68be6
- `postman/postman_collection.json` rewritten: "D5 Security Layer" — folders Auth (logins for admin_01/hr_01/clinician_01 storing `token`/`refresh_token`/`hr_token`/`cli_token` vars, refresh rotation, whoami), Invoke — guardrail scenarios (13: pass + all 5 layers), Audit/traces/observability (8). Fixed stale `user_id` login body → `username`
- `.env.example` synced with all 42 settings fields (added JWT_ISSUER/AUDIENCE, AUTH_MAX_FAILED_ATTEMPTS/AUTH_LOCKOUT_MINUTES, AUTH_LOGIN/REFRESH_RATE_LIMIT, TRUST_PROXY_COUNT); verified programmatically — no missing keys
- Doc fixes: README/RUNBOOK pointed to real openssl keygen (gen_keys.py never existed); presidio install instructions corrected (no `[full]` extra)

## Verification
- `py -m ruff check app/ tests/ scripts/` → All checks passed
- `py -m mypy app/` → Success, no issues (53 source files)
- `py -m pytest -q --no-header` → **132 passed**
- Live (fresh server restart on :8000): `/health/live` + `/health/ready` 200; smoke 13/13 with correct block codes per layer; `/traces` persisted; `/metrics` shows HTTP + all guardrail decision counters

## Notes / Follow-ups
- CI workflow yaml-validated with pyyaml only — first real run happens on first push to GitHub (no runner here)
- Docker build verification still pending a Docker-capable machine (Phase 3 carry-over)
- `/metrics` unauthenticated by design (scrape-level protection)
- mypy covers `app/` only; scripts/ excluded
