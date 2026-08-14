"""
app.core.guardrails.ingress.pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Assembles all ingress guardrail layers into a single GuardrailPipeline singleton.

Usage
-----
    from app.core.guardrails.ingress import ingress_pipeline

    try:
        await ingress_pipeline.run(input_text, context, user, trace_id=trace_id)
    except GuardrailException as exc:
        # exc.result carries code, message, layer, details
        raise HTTPException(status_code=..., detail=exc.result.to_dict())
"""
from app.core.guardrails.base import GuardrailPipeline
from app.core.guardrails.ingress.layer1_file import (
    FileSizeGuard,
    FileTypeGuard,
    MimeTypeGuard,
)
from app.core.guardrails.ingress.layer1_schema import (
    ContextDepthGuard,
    EncodingAnomalyGuard,
    ForbiddenKeyGuard,
    UTF8BudgetGuard,
)
from app.core.guardrails.ingress.layer2_file_phi import FilePhiGuard
from app.core.guardrails.ingress.layer2_semantic import SemanticInjectionGuard
from app.core.guardrails.ingress.layer2_security import (
    DelimiterHijackGuard,
    EncodedPayloadGuard,
    ExcessiveRepetitionGuard,
    PHIInInputGuard,
    PromptInjectionGuard,
)
from app.core.guardrails.ingress.layer3_policy import (
    ConsentGuard,
    PHIAccessEntitlementGuard,
    RBACTokenBudgetGuard,
)
from app.core.guardrails.ingress.layer3_tenant_guard import TenantIsolationGuard
from app.core.guardrails.ingress.layer4_content import (
    LanguageGuard,
    TopicScopeGuard,
)
from app.core.guardrails.ingress.layer5_llm import LLMEvaluatorGuard


def build_ingress_pipeline() -> GuardrailPipeline:
    """
    Factory that constructs the ordered ingress guardrail pipeline.

    Guard execution order is intentional:
      File L1 (type/size/MIME — cheapest, no-op on text-only requests) →
      L1 (text structural) → L2 (regex + file PHI) → L2.5 (semantic embeddings) →
      L3 (business rules & Tenant Isolation) → L4 (heuristics) → L5 (LLM)

    Each layer short-circuits the rest if it blocks.
    """
    return GuardrailPipeline(
        guards=[
            # ── File Layer 1 – Type / Size / MIME (no-op if no file) ─────────
            FileTypeGuard(),
            FileSizeGuard(),
            MimeTypeGuard(),

            # ── Layer 1 – Structural (text) ───────────────────────────────────
            UTF8BudgetGuard(),
            ContextDepthGuard(max_depth=3, max_keys=20),
            ForbiddenKeyGuard(),
            EncodingAnomalyGuard(),

            # ── Layer 2 – Security + File PHI ─────────────────────────────────
            PromptInjectionGuard(),
            DelimiterHijackGuard(),
            EncodedPayloadGuard(),
            ExcessiveRepetitionGuard(),
            PHIInInputGuard(),          # warn-only: PHI in the text input
            FilePhiGuard(),             # warn-only: PHI in CSV/PDF file content

            # ── Layer 2.5 – Semantic Embedding Injection Guard ───────────────
            SemanticInjectionGuard(),   # embedding similarity (typo/paraphrase proof)

            # ── Layer 3 – Policy & Tenant Isolation ───────────────────────────
            TenantIsolationGuard(),     # Blocks cross-tenant context injection
            ConsentGuard(),
            RBACTokenBudgetGuard(),
            PHIAccessEntitlementGuard(),

            # ── Layer 4 – Content Scope ───────────────────────────────────────
            TopicScopeGuard(),          # warn by default
            LanguageGuard(),            # warn by default

            # ── Layer 5 – LLM Evaluator ───────────────────────────────────────
            LLMEvaluatorGuard(),        # Gemini / LLM semantic evaluation
        ]
    )


# Pre-built singleton – avoids re-compiling regex patterns on every request
ingress_pipeline: GuardrailPipeline = build_ingress_pipeline()
