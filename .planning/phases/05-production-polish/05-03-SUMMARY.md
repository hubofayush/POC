# 05-03 SUMMARY — Input Guardrails

Status: **COMPLETE** — all waves delivered, gates green (ruff 26 pre-existing / mypy 52 < baseline 54 / pytest 236 passed).

## Delivered

### Wave 1 — Content moderation categories
- `ContentModerationGuard` (app/core/guardrails/ingress/layer4_harmful.py) — hate speech, insults,
  sexual content, misconduct; per-category lexicon + semantic template banks, block default
  (`GUARDRAIL_MODERATION_MODE=block`, threshold 0.75). Wired into ingress pipeline.
- tests/test_moderation_guard.py (6 tests)

### Wave 2 — Denied topics
- `DeniedTopicGuard` (app/core/guardrails/ingress/layer4_content.py) — configurable deny-list via
  `GUARDRAIL_DENIED_TOPICS` (comma-separated), own mode `GUARDRAIL_DENIED_TOPIC_MODE=block`.
- tests/test_denied_topics.py (4 tests)

### Wave 3 — PHI input masking before D3
- `PHIInInputGuard` now stashes `context["_masked_input"]` via the hybrid PHI masker (regex +
  Presidio NLP), gated by `GUARDRAIL_INPUT_PHI_MASK=True`. `services/invoke.py` forwards the
  masked text to D3 (same `_filtered_output` contract as egress).
- tests/test_phi_input_masking.py (3 tests)

### Wave 4 — Word filters (both directions)
- Shared blocklist module app/core/guardrails/wordlist.py (curated set + leetspeak-normalized
  matching + `GUARDRAIL_WORD_FILTER_WORDS` extension).
- Ingress `WordFilterGuard` (layer2_wordlist.py) — blocks profanity on input (block default).
- Egress `ProfanityMaskGuard` (egress/layer4_wordlist.py) — masks tokens with `[FILTERED]` into
  `_filtered_output`, response preserved; runs last after RBAC redaction.
- tests/test_word_filter.py (9 tests incl. leetspeak bypass + chaining)

### Wave 5 — Contextual grounding (embedding-based)
- `SemanticGroundingGuard` (egress/layer3_grounding.py) — MiniLM cosine similarity between output
  and citation chunks, complements term-overlap `CitationCoverageGuard`; honors
  `GUARDRAIL_EGRESS_GROUNDING_MODE` warn/block.
- tests/test_semantic_grounding.py (5 tests)

### Wave 6 — WIP commit + verification
- Committed pre-session WIP: shared `get_encoder` MiniLM cache, `gemini-3.1-flash-lite` alias,
  sentence-transformers dependency, harmful-guard tests, lint cleanup.
- Full suite: 236 passed; 2 pre-existing env-dependent failures confirmed on clean HEAD
  (live Gemini L5 false positive on a test query; Presidio model labels "name" as PERSON).

## Decisions
| Date | Decision |
| ---- | -------- |
| 2026-08-17 | New filters default block; egress profanity masks (never blocks response) |
| 2026-08-17 | Input PHI masked inside the pipeline (`_masked_input`), not just at invoke layer |
| 2026-08-17 | Word-list matcher local _normalise copy (avoids circular import via package __init__) |
| 2026-08-17 | Pre-existing untracked WIP (ingress stage1–6 dirs) left uncommitted — not part of this plan |

## Known pre-existing failures (not from this plan)
- tests/test_invoke.py::test_invoke_missing_check — live Gemini L5 flags "What credentials are
  missing?" as INDIRECT_INJECTION (environment/API dependent).
- tests/test_phi.py::test_detect_nurse_name — Presidio spaCy model returns PERSON, not name.
- tests/test_rate_limit_proxy.py — collection ImportError `_proxy_aware_key` (pre-existing).
- ruff 26 errors and mypy 52 errors exist at baseline (untracked stage* WIP dirs).