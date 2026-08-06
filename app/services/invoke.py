"""
app.services.invoke
~~~~~~~~~~~~~~~~~~~
Service layer orchestrating ingress guardrails, PHI masking, downstream D3 API call,
egress policy filtering, production audit logging, and trace span recording.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from app.schemas import InvokeRequest, InvokeResponse
from app.core.phi.masker import mask_phi
from app.core.tracing import tracer
from app.core.audit import log_entry
from app.core.logging import get_logger
from app.core.security.rbac import check_org
from app.integrations.d3_client import d3_client, D3CallError
from app.services.ingress import run_ingress_guardrails
from app.services.egress import verify_citations, filter_by_role

logger = get_logger(__name__)


async def process_invoke(
    request: InvokeRequest,
    user: dict[str, Any],
    client_ip: str = "unknown",
    user_agent: str = "unknown",
) -> InvokeResponse:
    t0 = time.monotonic()
    trace_id = str(uuid4())
    input_bytes = len(request.input.encode("utf-8"))
    user_org = user.get("org", "unknown")

    # --- TENANT ISOLATION: context-supplied org must match the JWT org ---
    check_org(user, request.context.get("org"))

    # --- INITIALIZE TRACE ---
    await tracer.create_trace(
        user=user["sub"],
        action="invoke",
        input_preview=request.input[:100],
        trace_id=trace_id,
        org=user_org,
    )

    # --- INGRESS GUARDRAILS (5-Layer Pipeline) ---
    logger.info(
        "ingress.start",
        user_id=user["sub"],
        role=user["role"],
        org=user_org,
        client_ip=client_ip,
        input_length=len(request.input),
        context_keys=list(request.context.keys()),
    )

    guardrail_span = await tracer.create_span(trace_id, "ingress_guardrails_pipeline")
    try:
        await run_ingress_guardrails(
            input_text=request.input,
            context=request.context,
            user=user,
            trace_id=trace_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await tracer.end_span(guardrail_span, {"status": "passed"})
    except Exception as exc:
        await tracer.end_span(guardrail_span, {"status": "blocked", "error": str(exc)})
        await tracer.end_trace(trace_id, status="blocked", metadata={"error": str(exc)})
        raise

    logger.info("ingress.guardrails.passed", trace_id=trace_id)

    # PHI Masking Rule (as specified):
    # requires_phi == True  (default) -> Enable PHI Masking
    # requires_phi == False           -> Disable PHI Masking for privileged roles (admin / compliance)
    requires_phi = request.context.get("requires_phi", True)
    user_role = user.get("role", "hr")

    async def _mask(text: str) -> str:
        # Regex + Presidio NLP masking is CPU-bound; run off the event loop
        return await asyncio.to_thread(mask_phi, text, "hr")

    if requires_phi:
        # Masking ON
        safe_input = await _mask(request.input)
    else:
        # Masking OFF for authorized roles
        if user_role in ("admin", "compliance_officer"):
            safe_input = request.input
        else:
            safe_input = await _mask(request.input)

    logger.info(
        "ingress.phi_masked",
        original_length=len(request.input),
        masked_length=len(safe_input),
        safe_input=safe_input,
    )

    # --- D3 CALL ---
    d3_payload = {
        "input": safe_input,
        "context": request.context,
    }

    logger.info("d3.call", trace_id=trace_id, payload=d3_payload)

    d3_span = await tracer.create_span(trace_id, "d3_client_execution")
    try:
        d3_resp = await d3_client.call_invoke(
            trace_id=trace_id,
            input=safe_input,
            context=request.context,
        )
    except D3CallError as exc:
        await tracer.end_span(d3_span, {"status": "failed", "error": str(exc)})
        await tracer.end_trace(trace_id, status="failed", metadata={"error": str(exc)})
        await log_entry(
            user_id=user["sub"],
            user_role=user_role,
            user_org=user_org,
            client_ip=client_ip,
            user_agent=user_agent,
            request_path="/invoke",
            http_method="POST",
            latency_ms=round((time.monotonic() - t0) * 1000, 2),
            input_bytes=input_bytes,
            action="invoke",
            resource_type="compliance_check",
            resource_id=request.context.get("clinician_id", "unknown"),
            phi_accessed=not requires_phi,
            status="block",
            guardrail_code="D3_UNAVAILABLE",
            guardrail_layer="egress.d3",
            trace_id=trace_id,
            details=f"error={type(exc).__name__}: {exc}",
        )
        logger.error(
            "egress.d3.failed",
            trace_id=trace_id,
            error=type(exc).__name__,
            msg="D3 downstream unavailable; returning 503",
        )
        raise HTTPException(
            status_code=503,
            detail="Downstream service unavailable. Please retry shortly.",
        ) from exc
    await tracer.end_span(d3_span, {"tier": d3_resp.get("tier", "unknown")})

    logger.info(
        "d3.response",
        trace_id=trace_id,
        output_preview=d3_resp.get("output", "")[:100],
        citations=d3_resp.get("citations", []),
        tier=d3_resp.get("tier", "unknown"),
    )

    # --- EGRESS PHI MASKING ---
    if requires_phi:
        raw_output = await _mask(d3_resp["output"])
    else:
        if user_role in ("admin", "compliance_officer"):
            raw_output = d3_resp["output"]
        else:
            raw_output = await _mask(d3_resp["output"])

    safe_output = filter_by_role(raw_output, user_role)
    citations = verify_citations(safe_output, d3_resp.get("citations", []))

    citation_warning = None
    if not citations:
        citation_warning = (
            "The output may not be fully grounded in the provided citations. "
            "Verify critical information independently."
        )

    latency_ms = round((time.monotonic() - t0) * 1000, 2)

    logger.info(
        "egress.result",
        output_preview=safe_output[:100],
        citation_count=len(citations),
        tier=d3_resp.get("tier"),
        citation_warning=citation_warning,
        latency_ms=latency_ms,
    )

    # --- AUDIT (PRODUCTION SOC2/HIPAA Standard) ---
    audit_id = await log_entry(
        user_id=user["sub"],
        user_role=user_role,
        user_org=user_org,
        client_ip=client_ip,
        user_agent=user_agent,
        request_path="/invoke",
        http_method="POST",
        latency_ms=latency_ms,
        input_bytes=input_bytes,
        action="invoke",
        resource_type="compliance_check",
        resource_id=request.context.get("clinician_id", "unknown"),
        phi_accessed=not requires_phi,
        status="success",
        trace_id=trace_id,
        details=f"tier={d3_resp.get('tier', 'unknown')}",
    )

    logger.info("audit.logged", audit_id=audit_id, trace_id=trace_id)

    # --- CLOSE TRACE SUCCESSFULLY ---
    await tracer.end_trace(
        trace_id,
        status="success",
        metadata={
            "audit_id": audit_id,
            "latency_ms": latency_ms,
            "tier_used": d3_resp.get("tier", "cheap"),
        },
    )

    metadata = {
        "audit_id": audit_id,
        "trace_id": trace_id,
        "phi_masked": requires_phi,
        "tier_used": d3_resp.get("tier", "cheap"),
        "latency_ms": latency_ms,
        "d3_payload": d3_payload,
    }

    if citation_warning:
        metadata["warning"] = citation_warning

    logger.info(
        "invoke.complete",
        audit_id=audit_id,
        trace_id=trace_id,
        tier=d3_resp.get("tier"),
        latency_ms=latency_ms,
        phi_masked=requires_phi,
    )

    return InvokeResponse(
        output=safe_output,
        citations=citations,
        metadata=metadata,
    )
