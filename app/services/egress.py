"""
app.services.egress
~~~~~~~~~~~~~~~~~~~~
Egress service: the public entry point for the 5-layer egress guardrail pipeline.

run_egress_guardrails()  – run the full egress pipeline; raises GuardrailException
                            and persists rich forensic audit events on failure.

Returns the filtered output text (from RoleBasedOutputFilterGuard) on success.

Legacy helpers kept for backward-compatibility:
    filter_by_role()    – simple regex-based role redaction (superseded by EL4-c)
    verify_citations()  – pass-through citation verifier (superseded by EL3)
"""
from __future__ import annotations

import re
import time
from typing import Any

from app.core.audit import log_guardrail_event
from app.core.guardrails.base import GuardrailException
from app.core.guardrails.egress import egress_pipeline
from app.core.logging import get_logger
from app.observability import metrics

logger = get_logger(__name__)


async def run_egress_guardrails(
    output_text: str,
    context: dict[str, Any],
    user: dict[str, Any],
    citations: list[Any],
    trace_id: str = "",
    client_ip: str = "unknown",
    user_agent: str = "unknown",
) -> str:
    """
    Run the full 5-layer egress guardrail pipeline against the LLM output.

    Parameters
    ----------
    output_text : str
        Raw LLM response text (before masking).
    context : dict
        Request context dict. The function injects ``_egress_citations`` into
        this dict so EL3 (citation coverage guard) can access them without
        changing the BaseGuardrail signature.
    user : dict
        JWT-decoded user claims (sub, role, org).
    citations : list[str]
        Citations returned by the D3 model.
    trace_id : str
        Correlation ID for the current request trace.
    client_ip / user_agent : str
        Forwarded from the HTTP request for audit logging.

    Returns
    -------
    str
        Role-filtered output text (produced by RoleBasedOutputFilterGuard).
        Falls back to the original ``output_text`` if the filter guard did not
        write to ``context["_filtered_output"]``.

    Raises
    ------
    GuardrailException
        On any blocking egress guardrail failure.  The caller must convert this
        to an HTTP 500 response and suppress the output entirely.
    """
    t0 = time.monotonic()
    output_bytes = len(output_text.encode("utf-8"))
    user_org = user.get("org", "unknown")

    # Inject citations into context for EL3 (citation coverage guard)
    egress_context = {**context, "_egress_citations": citations}

    logger.info(
        "guardrail.egress.pipeline.start",
        trace_id=trace_id,
        user_id=user.get("sub"),
        role=user.get("role"),
        org=user_org,
        output_length=len(output_text),
        citation_count=len(citations),
    )

    try:
        results = await egress_pipeline.run(
            input_text=output_text,
            context=egress_context,
            user=user,
            trace_id=trace_id,
        )

        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        metrics.GUARDRAIL_DECISIONS.labels(
            layer="egress.pipeline", decision="pass", code="EGRESS_PIPELINE_PASSED"
        ).inc()
        logger.info(
            "guardrail.egress.pipeline.passed",
            trace_id=trace_id,
            guards_run=len(results),
            latency_ms=latency_ms,
        )

        # Persist audit event (non-blocking on failure)
        try:
            await log_guardrail_event(
                user_id=user.get("sub", "unknown"),
                user_role=user.get("role", "unknown"),
                user_org=user_org,
                client_ip=client_ip,
                user_agent=user_agent,
                latency_ms=latency_ms,
                input_bytes=output_bytes,
                trace_id=trace_id,
                guardrail_layer="egress.pipeline",
                guardrail_code="EGRESS_PIPELINE_PASSED",
                passed=True,
                details=f"guards_run={len(results)},citations={len(citations)}",
            )
        except Exception as audit_err:
            logger.warning("guardrail.egress.audit.write_failed", error=str(audit_err))

        # Return role-filtered output (written by RoleBasedOutputFilterGuard)
        return egress_context.get("_filtered_output", output_text)

    except GuardrailException as exc:
        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        result = exc.result
        metrics.GUARDRAIL_DECISIONS.labels(
            layer=result.layer, decision="block", code=result.code
        ).inc()
        logger.error(
            "guardrail.egress.pipeline.blocked",
            trace_id=trace_id,
            code=result.code,
            layer=result.layer,
            message=result.message,
            user_id=user.get("sub"),
            latency_ms=latency_ms,
        )

        # Persist audit event for the blocked response
        try:
            await log_guardrail_event(
                user_id=user.get("sub", "unknown"),
                user_role=user.get("role", "unknown"),
                user_org=user_org,
                client_ip=client_ip,
                user_agent=user_agent,
                latency_ms=latency_ms,
                input_bytes=output_bytes,
                trace_id=trace_id,
                guardrail_layer=result.layer,
                guardrail_code=result.code,
                passed=False,
                details=str(result.details),
            )
        except Exception as audit_err:
            logger.warning("guardrail.egress.audit.write_failed", error=str(audit_err))

        raise


# ---------------------------------------------------------------------------
# Legacy helpers — kept for import compatibility
# Functionality superseded by EL4-c (RoleBasedOutputFilterGuard) and
# EL3-a (CitationCoverageGuard) respectively.
# ---------------------------------------------------------------------------

def verify_citations(output: str, citations: list[Any]) -> list[Any]:
    """
    Legacy citation pass-through.
    Citation grounding is now handled by CitationCoverageGuard (EL3-a).
    This function returns the citations unchanged for backward compatibility.
    """
    return citations


def filter_by_role(output: str, user_role: str) -> str:
    """
    Legacy role-based output filter.
    Superseded by RoleBasedOutputFilterGuard (EL4-c) in the egress pipeline.
    Kept here so any direct callers continue to compile without changes.
    """
    if user_role in ("hr", "clinician"):
        sensitive = ["diagnosis", "treatment", "prescription", "medication"]
        for word in sensitive:
            output = re.sub(rf"\b{word}\b", "[REDACTED]", output, flags=re.IGNORECASE)
    return output
