"""
app.core.guardrails.egress.pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Assembles all egress guardrail layers into a single GuardrailPipeline singleton.

Usage
-----
    from app.core.guardrails.egress import egress_pipeline

    filtered_output = await run_egress_guardrails(
        output_text=d3_resp["output"],
        context=request.context,
        user=user,
        citations=d3_resp.get("citations", []),
        trace_id=trace_id,
    )

Important
---------
The RoleBasedOutputFilterGuard (EL4-c) writes its filtered output to
context["_filtered_output"]. Callers must read this key after a successful
pipeline run to obtain the role-filtered response text.
"""
from app.core.guardrails.base import GuardrailPipeline
from app.core.guardrails.egress.layer1_structure import (
    OutputEncodingAnomalyGuard,
    OutputSizeLimitGuard,
)
from app.core.guardrails.egress.layer2_phi import PHILeakGuard
from app.core.guardrails.egress.layer3_grounding import (
    CitationCoverageGuard,
    HallucinationPatternGuard,
)
from app.core.guardrails.egress.layer4_policy import (
    ForbiddenDisclosureGuard,
    RoleBasedOutputFilterGuard,
    ToxicOutputGuard,
)
from app.core.guardrails.egress.layer4_wordlist import ProfanityMaskGuard
from app.core.guardrails.egress.layer5_llm import LLMOutputEvaluatorGuard


def build_egress_pipeline() -> GuardrailPipeline:
    """
    Factory that constructs the ordered egress guardrail pipeline.

    Guard execution order is intentional (cheapest → most expensive):
      EL1 (structural)  → EL2 (PHI/NLP)  → EL3 (heuristic grounding)
      → EL4 (content policy) → EL5 (LLM semantic evaluation)

    Each layer short-circuits the rest if it blocks.
    """
    return GuardrailPipeline(
        guards=[
            # ── EL1 – Structural Integrity ────────────────────────────────
            OutputSizeLimitGuard(),
            OutputEncodingAnomalyGuard(),

            # ── EL2 – PHI / PII Leak Prevention ──────────────────────────
            PHILeakGuard(),                   # fires BEFORE mask_phi()

            # ── EL3 – Hallucination & Citation Grounding ──────────────────
            CitationCoverageGuard(),          # term-overlap coverage check
            HallucinationPatternGuard(),      # regex-based hallucination signals

            # ── EL4 – Content Policy ──────────────────────────────────────
            ToxicOutputGuard(),               # hate speech / violent language
            ForbiddenDisclosureGuard(),       # system prompt / CoT / API key leakage
            RoleBasedOutputFilterGuard(),     # RBAC clinical-term redaction (always passes)
            ProfanityMaskGuard(),             # last: mask blocked words in output

            # ── EL5 – LLM Output Semantic Evaluator ───────────────────────
            LLMOutputEvaluatorGuard(),        # Gemini semantic safety re-check
        ]
    )


# Pre-built singleton — avoids re-compiling regex patterns on every request
egress_pipeline: GuardrailPipeline = build_egress_pipeline()
