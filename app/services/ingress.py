"""
app.services.ingress
~~~~~~~~~~~~~~~~~~~~~
Ingress service: the public entry point for the 5-layer guardrail pipeline.

run_ingress_guardrails()  – run the full pipeline; raises GuardrailException
                             and persists rich forensic audit events.
"""
from __future__ import annotations

import re
import time
from typing import Any

from app.core.audit import log_guardrail_event
from app.core.guardrails.base import GuardrailException
from app.core.guardrails.pipeline import ingress_pipeline
from app.core.logging import get_logger
from app.observability import metrics

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Legacy helpers (kept for import compatibility; used internally by Layer 2/3)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    r"(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?)",
    r"(?:you\s+are\s+now|act\s+as|pretend\s+to\tbe|assume\s+the\s+role\s+of)\s+(?:an?\s+)?(?:unrestricted|DAN|jailbroken|developer|admin|system|root)",
    r"you\s+must\s+(?:now\s+)?(?:follow|obey|answer)\s+(?:only|my)\s+(?:new\s+)?instructions",
    r"(?:show|print|display|reveal|output|repeat|share|dump)\s+(?:me\s+)?(?:the\s+)?(?:system|initial|original|developer)\s+(?:prompt|instructions?|rules?)",
    r"what\s+(?:are|were)\s+your\s+(?:original|initial|system)\s+(?:instructions?|prompts?)",
    r"<\s*/?s*(?:system|im_start|im_end|instruction|human|assistant|user)\s*>",
    r"\[\s*/?s*(?:INST|SYS|SYSTEM)\s*\]",
    r"```\s*(?:json|xml|markdown)?\s*\n\s*(?:system|override|ignore)",
    r"(?:base64|hex|rot13|url)\s+(?:encoded?|decoder?|string)",
    r"decode\s+and\s+(?:execute|run|follow)",
    r"(?:do\s+not|stop)\s+(?:follow|enforc|apply)ing?\s+(?:security|safety|hipaa|phi)\s+(?:rules?|policy|policies|guidelines?)",
    r"(?:disregard|ignore)\s+(?:hipaa|privacy|compliance)\s+(?:protocol|rules?|restrictions?)",
    r"(?:from\s+now\s+on|henceforth),\s*you\s+(?:will|can|should)\s+do\s+anything",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in INJECTION_PATTERNS]


def normalize_input(text: str) -> str:
    text = re.sub(r"[\u200B-\u200D\uFEFF\x00-\x1F\x7F]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def check_consent(context: dict) -> bool:
    return context.get("consent_granted", True)


def check_injection(text: str) -> bool:
    normalized_text = normalize_input(text)
    return all(not pattern.search(normalized_text) for pattern in COMPILED_PATTERNS)


# ---------------------------------------------------------------------------
# Production pipeline entry point
# ---------------------------------------------------------------------------

async def run_ingress_guardrails(
    input_text: str,
    context: dict[str, Any],
    user: dict[str, Any],
    trace_id: str = "",
    client_ip: str = "unknown",
    user_agent: str = "unknown",
) -> None:
    """
    Run the full 5-layer ingress guardrail pipeline.

    On success: returns None and the request may proceed.
    On failure: persists a rich guardrail_check audit entry, then raises
               GuardrailException.
    """
    t0 = time.monotonic()
    input_bytes = len(input_text.encode("utf-8"))
    user_org = user.get("org", "unknown")

    logger.info(
        "guardrail.pipeline.start",
        trace_id=trace_id,
        user_id=user.get("sub"),
        role=user.get("role"),
        org=user_org,
        client_ip=client_ip,
        input_length=len(input_text),
    )

    try:
        results = await ingress_pipeline.run(
            input_text=input_text,
            context=context,
            user=user,
            trace_id=trace_id,
        )

        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        metrics.GUARDRAIL_DECISIONS.labels(
            layer="pipeline", decision="pass", code="PIPELINE_PASSED"
        ).inc()
        logger.info(
            "guardrail.pipeline.passed",
            trace_id=trace_id,
            guards_run=len(results),
            latency_ms=latency_ms,
        )

        try:
            await log_guardrail_event(
                user_id=user.get("sub", "unknown"),
                user_role=user.get("role", "unknown"),
                user_org=user_org,
                client_ip=client_ip,
                user_agent=user_agent,
                latency_ms=latency_ms,
                input_bytes=input_bytes,
                trace_id=trace_id,
                guardrail_layer="pipeline",
                guardrail_code="PIPELINE_PASSED",
                passed=True,
                details=f"guards_run={len(results)}",
            )
        except Exception as audit_err:
            logger.warning("guardrail.audit.write_failed", error=str(audit_err))

    except GuardrailException as exc:
        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        result = exc.result
        metrics.GUARDRAIL_DECISIONS.labels(
            layer=result.layer, decision="block", code=result.code
        ).inc()
        logger.warning(
            "guardrail.pipeline.blocked",
            trace_id=trace_id,
            code=result.code,
            layer=result.layer,
            message=result.message,
            user_id=user.get("sub"),
            latency_ms=latency_ms,
        )

        try:
            await log_guardrail_event(
                user_id=user.get("sub", "unknown"),
                user_role=user.get("role", "unknown"),
                user_org=user_org,
                client_ip=client_ip,
                user_agent=user_agent,
                latency_ms=latency_ms,
                input_bytes=input_bytes,
                trace_id=trace_id,
                guardrail_layer=result.layer,
                guardrail_code=result.code,
                passed=False,
                details=str(result.details),
            )
        except Exception as audit_err:
            logger.warning("guardrail.audit.write_failed", error=str(audit_err))

        raise