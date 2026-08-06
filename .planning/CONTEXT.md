# D5 Security Layer — Project Context

## Vision
A production-ready enterprise security gateway protecting healthcare/compliance AI
calls (D3 downstream): 5-layer ingress guardrails, PHI/PII detection & masking
(Presidio), RBAC + tenant isolation, tamper-evident audit trail, and distributed
tracing — hardened from POC to production.

## Tech Stack
- FastAPI (async) + uvicorn, Pydantic v2, SQLAlchemy 2 async (SQLite dev / Postgres prod)
- Alembic migrations, JWT RS256, argon2 (pwdlib) password hashing
- Presidio Analyzer/Anonymizer + spaCy NLP
- structlog, slowapi, httpx
- Tests: pytest + pytest-asyncio (baseline 68 passing)

## Production Readiness Roadmap
- Phase 0 (governance): CI, ruff/mypy, dependency pinning — deferred, not started
- **Phase 1 (current): Security hardening — auth rework (real user store, refresh
  rotation), org isolation, CORS allowlist, LLM guard fixes, response sanitization,
  body/auth rate limits, PHI fail-open + alarm, consent default-deny**
- Phase 2: reliability — alembic completion, audit hash chaining, trace persistence,
  async offload, egress hardening
- Phase 3: observability & ops — metrics, health readiness, docker hardening, proxy
- Phase 4: test isolation, CI gates, docs/runbooks, postman update

## Key Decisions (from plan)
1. Real user store in Postgres (argon2), refresh-token rotation + reuse detection
2. Keep mock D3 client behind hardened interface (timeout/retry/circuit breaker in Phase 2)
3. Docker Compose single-host deployment
4. Consent: default-deny when `consent_granted` absent
5. Compliance officer audit/traces: org-scoped; admin cross-org
6. PHI detection errors: fail-open + explicit alarm logging (no silent downgrade)
7. Auth API breaking change accepted (MOCK_USERS removed)

## Constraints
- Python 3.14 runtime (project env), Python 3.12 also present on machine
- Dev server runs on port 8000 with --reload; d5_dev.db may be file-locked
- Must keep all existing tests green unless deliberately changed (documented)
