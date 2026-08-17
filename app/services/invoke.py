"""
app.services.invoke
~~~~~~~~~~~~~~~~~~~
Service layer orchestrating ingress guardrails, PHI masking, downstream D3 API call,
egress policy filtering, production audit logging, and trace span recording.

Supports both text-only requests and file-attachment requests (CSV, PDF, PNG, JPG).
When a file_payload is provided the file metadata is injected into the guardrail
context so the file-specific guards (FileTypeGuard, FileSizeGuard, MimeTypeGuard,
FilePhiGuard) can evaluate the attachment.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncGenerator
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from app.core.audit import log_entry
from app.core.logging import get_logger
from app.core.phi.masker import mask_phi
from app.core.security.rbac import check_org
from app.core.tracing import tracer
from app.integrations.d3_client import D3CallError, d3_client
from app.repositories.document_repository import document_repository
from app.schemas import InvokeRequest, InvokeResponse
from app.services.egress import run_egress_guardrails
from app.services.ingress import run_ingress_guardrails

logger = get_logger(__name__)


async def process_invoke(
    request: InvokeRequest,
    user: dict[str, Any],
    client_ip: str = "unknown",
    user_agent: str = "unknown",
    file_payload: dict | None = None,
) -> InvokeResponse:
    """
    Orchestrate the full D5 security pipeline for a single /invoke call.

    Parameters
    ----------
    request : InvokeRequest
        Parsed request DTO (text input + context).
    user : dict
        Decoded JWT claims (sub, role, org).
    client_ip : str
        Client IP forwarded from the HTTP layer.
    user_agent : str
        User-Agent header value.
    file_payload : dict | None
        Present when the caller attached a file via POST /invoke/file.
        Keys: filename, extension, mime, size_bytes, raw_bytes.
    """
    t0 = time.monotonic()
    trace_id = str(uuid4())
    input_bytes = len(request.input.encode("utf-8"))
    user_org = user.get("org", "unknown")

    has_file = file_payload is not None

    # --- TENANT ISOLATION: context-supplied org must match the JWT org ---
    check_org(user, request.context.get("org"))

    # --- INITIALIZE TRACE ---
    await tracer.create_trace(
        user=user["sub"],
        action="invoke_file" if has_file else "invoke",
        input_preview=request.input[:100],
        trace_id=trace_id,
        org=user_org,
    )

    # ── Build guardrail context ──────────────────────────────────────────────
    # Inject file metadata into context so the file guards can read it.
    # These _file_* keys are internal signals; they are never exposed to D3
    # or returned to the caller.
    guardrail_context = dict(request.context)
    guardrail_context["_trace_id"] = trace_id

    if has_file:
        guardrail_context["_file_name"]      = file_payload["filename"]
        guardrail_context["_file_extension"] = file_payload["extension"]
        guardrail_context["_file_mime"]      = file_payload["mime"]
        guardrail_context["_file_size"]      = file_payload["size_bytes"]
        guardrail_context["_file_bytes"]     = file_payload["raw_bytes"]

    # --- INGRESS GUARDRAILS (5-Layer Pipeline + file guards if file present) ---
    logger.info(
        "ingress.start",
        user_id=user["sub"],
        role=user["role"],
        org=user_org,
        client_ip=client_ip,
        input_length=len(request.input),
        has_file=has_file,
        file_name=file_payload["filename"] if has_file else None,
        file_type=file_payload["extension"] if has_file else None,
    )

    guardrail_span = await tracer.create_span(trace_id, "ingress_guardrails_pipeline")

    # Persist the Document record early (in 'pending' state) so we have a
    # doc_id even if the guardrails block the request.
    doc_id: str | None = None
    if has_file:
        doc_id = await document_repository.create(
            uploader_id=user["sub"],
            org=user_org,
            filename=file_payload["filename"],
            file_type=file_payload["extension"],
            file_size_bytes=file_payload["size_bytes"],
            trace_id=trace_id,
        )
        logger.info("document.created", doc_id=doc_id, trace_id=trace_id)

    try:
        await run_ingress_guardrails(
            input_text=request.input,
            context=guardrail_context,
            user=user,
            trace_id=trace_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await tracer.end_span(guardrail_span, {"status": "passed"})
    except Exception as exc:
        await tracer.end_span(guardrail_span, {"status": "blocked", "error": str(exc)})
        await tracer.end_trace(trace_id, status="blocked", metadata={"error": str(exc)})
        if doc_id:
            await document_repository.mark_rejected(doc_id)
        raise

    logger.info("ingress.guardrails.passed", trace_id=trace_id)

    # ── PHI Masking ──────────────────────────────────────────────────────────
    # Prefer the mask computed inside the guardrail pipeline (Presidio
    # anonymize_pii, stashed as context["_masked_input"]); fall back to the
    # legacy mask_phi path when no PHI was flagged by the pipeline.
    masked_by_guard = guardrail_context.get("_masked_input")

    requires_phi = request.context.get("requires_phi", True)
    user_role = user.get("role", "hr")

    async def _mask(text: str) -> str:
        return await asyncio.to_thread(mask_phi, text, "hr")

    if masked_by_guard is not None:
        safe_input = masked_by_guard
    elif requires_phi:
        safe_input = await _mask(request.input)
    else:
        if user_role in ("admin", "compliance_officer"):
            safe_input = request.input
        else:
            safe_input = await _mask(request.input)

    logger.info(
        "ingress.phi_masked",
        original_length=len(request.input),
        masked_length=len(safe_input),
    )

    # ── Build D3 payload ──────────────────────────────────────────────────────
    # For file uploads:
    #   - PNG/JPG: pass raw bytes (base64-encoded) for D3's vision model
    #   - CSV/PDF: the guardrail extracted text is stored in guardrail_context;
    #              pass that masked text so D3 can reason about the content
    d3_context = dict(request.context)   # clean context, no _internal_ keys

    if has_file:
        ext = file_payload["extension"].lower()
        if ext in ("png", "jpg", "jpeg"):
            # Vision file: encode bytes for D3
            import base64
            d3_context["_file_name"] = file_payload["filename"]
            d3_context["_file_type"] = ext
            d3_context["_file_b64"]  = base64.b64encode(file_payload["raw_bytes"]).decode()
        else:
            # Text file: forward the guardrail-extracted (and optionally PHI-masked) text
            extracted = guardrail_context.get("_file_extracted_text", "")
            file_has_phi = guardrail_context.get("_file_text_has_phi", False)
            if file_has_phi and requires_phi:
                extracted = await _mask(extracted)
            d3_context["_file_name"]    = file_payload["filename"]
            d3_context["_file_type"]    = ext
            d3_context["_file_content"] = extracted

    d3_payload = {
        "input": safe_input,
        "context": d3_context,
    }

    logger.info("d3.call", trace_id=trace_id, has_file=has_file)

    # --- D3 CALL ---
    d3_span = await tracer.create_span(trace_id, "d3_client_execution")
    try:
        d3_resp = await d3_client.call_invoke(
            trace_id=trace_id,
            input=safe_input,
            context=d3_context,
        )
    except D3CallError as exc:
        await tracer.end_span(d3_span, {"status": "failed", "error": str(exc)})
        await tracer.end_trace(trace_id, status="failed", metadata={"error": str(exc)})
        if doc_id:
            await document_repository.mark_rejected(doc_id)
        await log_entry(
            user_id=user["sub"],
            user_role=user_role,
            user_org=user_org,
            client_ip=client_ip,
            user_agent=user_agent,
            request_path="/invoke/file" if has_file else "/invoke",
            http_method="POST",
            latency_ms=round((time.monotonic() - t0) * 1000, 2),
            input_bytes=input_bytes,
            action="invoke_file" if has_file else "invoke",
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

    # --- EGRESS GUARDRAIL PIPELINE (5-Layer) ---
    egress_span = await tracer.create_span(trace_id, "egress_guardrails_pipeline")
    try:
        pre_mask_output = await run_egress_guardrails(
            output_text=d3_resp["output"],
            context=request.context,
            user=user,
            citations=d3_resp.get("citations", []),
            trace_id=trace_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await tracer.end_span(egress_span, {"status": "passed"})
    except Exception as exc:
        await tracer.end_span(egress_span, {"status": "blocked", "error": str(exc)})
        await tracer.end_trace(trace_id, status="egress_blocked", metadata={"error": str(exc)})
        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        if doc_id:
            await document_repository.mark_rejected(doc_id)
        await log_entry(
            user_id=user["sub"],
            user_role=user_role,
            user_org=user_org,
            client_ip=client_ip,
            user_agent=user_agent,
            request_path="/invoke/file" if has_file else "/invoke",
            http_method="POST",
            latency_ms=latency_ms,
            input_bytes=input_bytes,
            action="invoke_file" if has_file else "invoke",
            resource_type="compliance_check",
            resource_id=request.context.get("clinician_id", "unknown"),
            phi_accessed=not requires_phi,
            status="block",
            guardrail_code=getattr(getattr(exc, "result", None), "code", "EGRESS_BLOCKED"),
            guardrail_layer=getattr(getattr(exc, "result", None), "layer", "egress.pipeline"),
            trace_id=trace_id,
            details=f"error={type(exc).__name__}: {exc}",
        )
        raise HTTPException(
            status_code=500,
            detail="Response suppressed by safety policy. Please rephrase your request.",
        ) from exc

    logger.info("egress.guardrails.passed", trace_id=trace_id)

    # --- EGRESS PHI MASKING ---
    if requires_phi:
        safe_output = await _mask(pre_mask_output)
    else:
        if user_role in ("admin", "compliance_officer"):
            safe_output = pre_mask_output
        else:
            safe_output = await _mask(pre_mask_output)

    citations = d3_resp.get("citations", [])
    citation_warning = None
    if not citations:
        citation_warning = (
            "The output may not be fully grounded in the provided citations. "
            "Verify critical information independently."
        )

    latency_ms = round((time.monotonic() - t0) * 1000, 2)

    # --- Mark document as indexed (D3 accepted it) ---
    if doc_id:
        d1_doc_id = d3_resp.get("metadata", {}).get("d1_doc_id") if isinstance(d3_resp.get("metadata"), dict) else None
        await document_repository.mark_indexed(doc_id, d1_doc_id=d1_doc_id)
        logger.info("document.indexed", doc_id=doc_id, d1_doc_id=d1_doc_id, trace_id=trace_id)

    # --- AUDIT (PRODUCTION SOC2/HIPAA Standard) ---
    audit_details = f"tier={d3_resp.get('tier', 'unknown')}"
    if has_file:
        audit_details += (
            f",file={file_payload['filename']}"
            f",file_type={file_payload['extension']}"
            f",file_size={file_payload['size_bytes']}"
            f",doc_id={doc_id}"
        )

    audit_id = await log_entry(
        user_id=user["sub"],
        user_role=user_role,
        user_org=user_org,
        client_ip=client_ip,
        user_agent=user_agent,
        request_path="/invoke/file" if has_file else "/invoke",
        http_method="POST",
        latency_ms=latency_ms,
        input_bytes=input_bytes,
        action="document_upload" if has_file else "invoke",
        resource_type="compliance_check",
        resource_id=request.context.get("clinician_id", "unknown"),
        phi_accessed=not requires_phi,
        status="success",
        trace_id=trace_id,
        details=audit_details,
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

    metadata: dict[str, Any] = {
        "audit_id": audit_id,
        "trace_id": trace_id,
        "phi_masked": requires_phi,
        "tier_used": d3_resp.get("tier", "cheap"),
        "latency_ms": latency_ms,
        "d3_payload": {k: v for k, v in d3_payload.items() if k != "context"},
    }

    if has_file:
        metadata["doc_id"]         = doc_id
        metadata["filename"]       = file_payload["filename"]
        metadata["file_type"]      = file_payload["extension"]
        metadata["file_size_bytes"] = file_payload["size_bytes"]

    if citation_warning:
        metadata["warning"] = citation_warning

    logger.info(
        "invoke.complete",
        audit_id=audit_id,
        trace_id=trace_id,
        tier=d3_resp.get("tier"),
        latency_ms=latency_ms,
        has_file=has_file,
        doc_id=doc_id,
    )

    return InvokeResponse(
        output=safe_output,
        citations=citations,
        metadata=metadata,
    )


async def process_invoke_stream(
    request: InvokeRequest,
    user: dict[str, Any],
    client_ip: str = "unknown",
    user_agent: str = "unknown",
    file_payload: dict | None = None,
) -> AsyncGenerator[str, None]:
    """
    Orchestrates real-time SSE streaming for /invoke calls.

    Emits SSE data frames:
      - Token chunk:  data: {"chunk": "...", "done": false}\n\n
      - Final result: data: {"citations": [...], "metadata": {...}, "done": true}\n\n
      - Error event:  data: {"error": "...", "message": "...", "done": true}\n\n
    """
    t0 = time.monotonic()
    trace_id = str(uuid4())
    input_bytes = len(request.input.encode("utf-8"))
    user_org = user.get("org", "unknown")
    user_role = user.get("role", "hr")
    has_file = file_payload is not None

    # --- TENANT ISOLATION ---
    try:
        check_org(user, request.context.get("org"))
    except Exception as exc:
        err_msg = json.dumps({"error": "TENANT_MISMATCH", "message": str(exc), "done": True})
        yield f"data: {err_msg}\n\n"
        return

    # --- INITIALIZE TRACE ---
    await tracer.create_trace(
        user=user["sub"],
        action="invoke_file_stream" if has_file else "invoke_stream",
        input_preview=request.input[:100],
        trace_id=trace_id,
        org=user_org,
    )

    # ── Build guardrail context ──────────────────────────────────────────────
    guardrail_context = dict(request.context)
    guardrail_context["_trace_id"] = trace_id

    if has_file:
        guardrail_context["_file_name"]      = file_payload["filename"]
        guardrail_context["_file_extension"] = file_payload["extension"]
        guardrail_context["_file_mime"]      = file_payload["mime"]
        guardrail_context["_file_size"]      = file_payload["size_bytes"]
        guardrail_context["_file_bytes"]     = file_payload["raw_bytes"]

    # --- INGRESS GUARDRAILS ---
    doc_id: str | None = None
    if has_file:
        doc_id = await document_repository.create(
            uploader_id=user["sub"],
            org=user_org,
            filename=file_payload["filename"],
            file_type=file_payload["extension"],
            file_size_bytes=file_payload["size_bytes"],
            trace_id=trace_id,
        )

    guardrail_span = await tracer.create_span(trace_id, "ingress_guardrails_pipeline")
    try:
        await run_ingress_guardrails(
            input_text=request.input,
            context=guardrail_context,
            user=user,
            trace_id=trace_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await tracer.end_span(guardrail_span, {"status": "passed"})
    except Exception as exc:
        await tracer.end_span(guardrail_span, {"status": "blocked", "error": str(exc)})
        await tracer.end_trace(trace_id, status="blocked", metadata={"error": str(exc)})
        if doc_id:
            await document_repository.mark_rejected(doc_id)
        code = getattr(getattr(exc, "result", None), "code", "INGRESS_BLOCKED")
        err_event = json.dumps({"error": code, "message": str(exc), "done": True})
        yield f"data: {err_event}\n\n"
        return

    # ── PHI Masking on input ──────────────────────────────────────────────────
    requires_phi = request.context.get("requires_phi", True)

    async def _mask(text: str) -> str:
        return await asyncio.to_thread(mask_phi, text, "hr")

    if requires_phi or user_role not in ("admin", "compliance_officer"):
        safe_input = await _mask(request.input)
    else:
        safe_input = request.input

    # ── Build D3 payload ──────────────────────────────────────────────────────
    d3_context = dict(request.context)
    if has_file:
        ext = file_payload["extension"].lower()
        if ext in ("png", "jpg", "jpeg"):
            import base64
            d3_context["_file_name"] = file_payload["filename"]
            d3_context["_file_type"] = ext
            d3_context["_file_b64"]  = base64.b64encode(file_payload["raw_bytes"]).decode()
        else:
            extracted = guardrail_context.get("_file_extracted_text", "")
            file_has_phi = guardrail_context.get("_file_text_has_phi", False)
            if file_has_phi and (requires_phi or user_role not in ("admin", "compliance_officer")):
                extracted = await _mask(extracted)
            d3_context["_file_name"]    = file_payload["filename"]
            d3_context["_file_type"]    = ext
            d3_context["_file_content"] = extracted

    d3_payload = {
        "input": safe_input,
        "context": d3_context,
    }

    # --- D3 STREAM CALL ---
    d3_span = await tracer.create_span(trace_id, "d3_client_execution_stream")
    full_output_acc: list[str] = []
    final_d3_response: dict = {}

    try:
        async for chunk, d3_resp in d3_client.stream_call_invoke(
            trace_id=trace_id, input=safe_input, context=d3_context
        ):
            if d3_resp is not None:
                final_d3_response = d3_resp
                break

            full_output_acc.append(chunk)

            # Apply real-time chunk masking if required
            if requires_phi or user_role not in ("admin", "compliance_officer"):
                safe_chunk = await _mask(chunk)
            else:
                safe_chunk = chunk

            chunk_evt = json.dumps({"chunk": safe_chunk, "done": False})
            yield f"data: {chunk_evt}\n\n"

    except Exception as exc:
        await tracer.end_span(d3_span, {"status": "failed", "error": str(exc)})
        await tracer.end_trace(trace_id, status="failed", metadata={"error": str(exc)})
        if doc_id:
            await document_repository.mark_rejected(doc_id)
        err_evt = json.dumps({"error": "D3_UNAVAILABLE", "message": "Downstream service error during streaming.", "done": True})
        yield f"data: {err_evt}\n\n"
        return

    await tracer.end_span(d3_span, {"tier": final_d3_response.get("tier", "unknown")})

    raw_output = "".join(full_output_acc)

    # --- EGRESS GUARDRAILS (Full Output) ---
    egress_span = await tracer.create_span(trace_id, "egress_guardrails_pipeline")
    try:
        pre_mask_output = await run_egress_guardrails(
            output_text=raw_output,
            context=request.context,
            user=user,
            citations=final_d3_response.get("citations", []),
            trace_id=trace_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await tracer.end_span(egress_span, {"status": "passed"})
    except Exception as exc:
        await tracer.end_span(egress_span, {"status": "blocked", "error": str(exc)})
        await tracer.end_trace(trace_id, status="egress_blocked", metadata={"error": str(exc)})
        if doc_id:
            await document_repository.mark_rejected(doc_id)
        err_evt = json.dumps({"error": "SAFETY_VIOLATION", "message": "Response suppressed by safety policy.", "done": True})
        yield f"data: {err_evt}\n\n"
        return

    citations = final_d3_response.get("citations", [])
    latency_ms = round((time.monotonic() - t0) * 1000, 2)

    # --- MARK DOCUMENT INDEXED ---
    if doc_id:
        d1_doc_id = final_d3_response.get("metadata", {}).get("d1_doc_id") if isinstance(final_d3_response.get("metadata"), dict) else None
        await document_repository.mark_indexed(doc_id, d1_doc_id=d1_doc_id)

    # --- AUDIT LOG ---
    audit_details = f"tier={final_d3_response.get('tier', 'unknown')},streaming=true"
    if has_file:
        audit_details += (
            f",file={file_payload['filename']}"
            f",file_type={file_payload['extension']}"
            f",file_size={file_payload['size_bytes']}"
            f",doc_id={doc_id}"
        )

    audit_id = await log_entry(
        user_id=user["sub"],
        user_role=user_role,
        user_org=user_org,
        client_ip=client_ip,
        user_agent=user_agent,
        request_path="/invoke/file" if has_file else "/invoke",
        http_method="POST",
        latency_ms=latency_ms,
        input_bytes=input_bytes,
        action="document_upload_stream" if has_file else "invoke_stream",
        resource_type="compliance_check",
        resource_id=request.context.get("clinician_id", "unknown"),
        phi_accessed=not requires_phi,
        status="success",
        trace_id=trace_id,
        details=audit_details,
    )

    await tracer.end_trace(
        trace_id,
        status="success",
        metadata={
            "audit_id": audit_id,
            "latency_ms": latency_ms,
            "tier_used": final_d3_response.get("tier", "cheap"),
            "streaming": True,
        },
    )

    metadata: dict[str, Any] = {
        "audit_id": audit_id,
        "trace_id": trace_id,
        "phi_masked": requires_phi,
        "tier_used": final_d3_response.get("tier", "cheap"),
        "latency_ms": latency_ms,
        "streaming": True,
    }
    if has_file:
        metadata["doc_id"]         = doc_id
        metadata["filename"]       = file_payload["filename"]
        metadata["file_type"]      = file_payload["extension"]
        metadata["file_size_bytes"] = file_payload["size_bytes"]

    final_payload = {
        "citations": citations,
        "metadata": metadata,
        "done": True,
    }
    yield f"data: {json.dumps(final_payload)}\n\n"

