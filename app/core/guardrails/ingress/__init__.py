"""
app.core.guardrails.ingress
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ingress guardrail pipeline — pre-flight checks on every incoming request.

The pipeline runs 5 ordered layers (cheapest → most expensive) and
short-circuits on the first failure.

Usage
-----
    from app.core.guardrails.ingress import ingress_pipeline

    try:
        await ingress_pipeline.run(input_text, context, user, trace_id=tid)
    except GuardrailException as exc:
        # exc.result carries code, message, layer, details
        ...

Layer guards are also individually importable for unit testing:
    from app.core.guardrails.ingress.layer1_schema import UTF8BudgetGuard
    from app.core.guardrails.ingress.layer2_security import PromptInjectionGuard
    ...
"""
from app.core.guardrails.ingress.pipeline import (  # noqa: F401
    build_ingress_pipeline,
    ingress_pipeline,
)

__all__ = ["ingress_pipeline", "build_ingress_pipeline"]
