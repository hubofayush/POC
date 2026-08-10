"""
app.core.guardrails.egress
~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress guardrail pipeline — post-flight checks on every LLM response.

The pipeline runs 5 ordered layers against the raw LLM output and
short-circuits on the first blocking failure.

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

Layer guards are also individually importable for unit testing:
    from app.core.guardrails.egress.layer2_phi import PHILeakGuard
    from app.core.guardrails.egress.layer4_policy import ToxicOutputGuard
    ...
"""
from app.core.guardrails.egress.pipeline import (  # noqa: F401
    build_egress_pipeline,
    egress_pipeline,
)

__all__ = ["egress_pipeline", "build_egress_pipeline"]
