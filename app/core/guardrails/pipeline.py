"""
app.core.guardrails.pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Assembles all four layers into a single GuardrailPipeline singleton.

Usage
-----
    from app.core.guardrails.pipeline import ingress_pipeline

    try:
        await ingress_pipeline.run(input_text, context, user, trace_id=trace_id)
    except GuardrailException as exc:
        # exc.result carries code, message, layer, details
        raise HTTPException(status_code=..., detail=exc.result.to_dict())
"""
from app.core.guardrails.base import GuardrailPipeline
from app.core.guardrails.layer1_schema import (
    UTF8BudgetGuard,
    ContextDepthGuard,
    ForbiddenKeyGuard,
    EncodingAnomalyGuard,
)
from app.core.guardrails.layer2_security import (
    PromptInjectionGuard,
    DelimiterHijackGuard,
    EncodedPayloadGuard,
    ExcessiveRepetitionGuard,
    PHIInInputGuard,
)
from app.core.guardrails.layer3_policy import (
    ConsentGuard,
    RBACTokenBudgetGuard,
    PHIAccessEntitlementGuard,
)
from app.core.guardrails.layer4_content import (
    TopicScopeGuard,
    LanguageGuard,
)
from app.core.guardrails.layer5_llm import LLMEvaluatorGuard



def build_ingress_pipeline() -> GuardrailPipeline:
    """
    Factory that constructs the ordered ingress guardrail pipeline.

    Guard execution order is intentional:
      L1 (cheapest) → L2 (regex) → L3 (business rules) → L4 (heuristics)

    Each layer short-circuits the rest if it blocks.
    """
    return GuardrailPipeline(
        guards=[
            # ── Layer 1 – Structural ──────────────────────────────────────
            UTF8BudgetGuard(),
            ContextDepthGuard(max_depth=3, max_keys=20),
            ForbiddenKeyGuard(),
            EncodingAnomalyGuard(),

            # ── Layer 2 – Security ────────────────────────────────────────
            PromptInjectionGuard(),
            DelimiterHijackGuard(),
            EncodedPayloadGuard(),
            ExcessiveRepetitionGuard(),
            PHIInInputGuard(),          # warn-only, always passes

            # ── Layer 3 – Policy ──────────────────────────────────────────
            ConsentGuard(),
            RBACTokenBudgetGuard(),
            PHIAccessEntitlementGuard(),

            # ── Layer 4 – Content Scope ───────────────────────────────────
            TopicScopeGuard(),          # warn by default
            LanguageGuard(),            # warn by default

            # ── Layer 5 – LLM Evaluator ───────────────────────────────────
            LLMEvaluatorGuard(),        # Gemini / LLM semantic evaluation
        ]
    )


# Pre-built singleton – avoids re-compiling regex patterns on every request
ingress_pipeline: GuardrailPipeline = build_ingress_pipeline()
