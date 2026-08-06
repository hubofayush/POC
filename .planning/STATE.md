# GSD STATE

Phase: 1 of 5 (Security Hardening)
Plan: 01-01 of 1 (auth rework, org isolation, CORS, LLM guard, response sanitization, limits, PHI alarm, consent)
Status: Plan 01-01 COMPLETE — awaiting checkpoint approval
Last activity: 2026-08-06 - Plan 01-01 executed (9 commits, all waves green)

Progress: ████████████████████ 100% (plan 01-01)

## Decisions
| Date | Decision |
| ---- | -------- |
| 2026-08-06 | Real user store in Postgres (argon2 hashing, refresh rotation) |
| 2026-08-06 | Keep mock D3 behind hardened interface |
| 2026-08-06 | Docker Compose single host |
| 2026-08-06 | Consent default-deny (flag GUARDRAIL_CONSENT_DEFAULT_GRANTED=false) |
| 2026-08-06 | Org-scoped audit/traces for compliance_officer; admin cross-org |
| 2026-08-06 | PHI detection errors: fail-open + explicit alarm logging |
| 2026-08-06 | Break old mock auth API (MOCK_USERS removed) |
| 2026-08-06 | Auth rate limits are per-IP and configurable (per-account lockout is separate) |
| 2026-08-06 | PHI alarm events use structured event `phi.detection.failed` (fail_mode=fail_open, layer, error_class) |
| 2026-08-06 | LLM guard: only `gemini` provider has HTTP integration; others log + local fallback |

## Issues / Blockers
- d5_dev.db file-locked by running dev server (uvicorn --reload port 8000) — leave on disk, gitignored
- Project Python env is 3.14 (`py -m pytest`), not 3.12 default `python`
- Dev server has no GEMINI_API_KEY → L5 smoke path exercises local fallback (real API path covered by tests with FakeGeminiClient)

## Session Continuity
Last session: 2026-08-06
Stopped at: Plan 01-01 complete — checkpoint pending approval (9 commits: dadbfa9..1f86aa7)
Resume file: .planning/phases/01-security-hardening/01-01-PLAN.md
