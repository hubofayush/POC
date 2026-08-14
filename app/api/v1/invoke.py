"""
app.api.v1.invoke
~~~~~~~~~~~~~~~~~
HTTP route handler for POST /invoke and POST /invoke/file.

Accepts text queries and file uploads, supporting both standard JSON/Response DTOs
and real-time Server-Sent Events (SSE) streaming when `stream=true` query param is provided.

Endpoints:
  1. POST /invoke?stream=true|false  — Content-Type: application/json
     Body: {"input": "...", "context": {...}, "client_trace_id": "..."}

  2. POST /invoke/file?stream=true|false  — Content-Type: multipart/form-data
     Fields: input, context (JSON string), file (CSV/PDF/PNG/JPG), client_trace_id
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from app.api.deps import get_current_user
from app.middleware.rate_limit import limiter
from app.schemas import InvokeRequest, InvokeResponse
from app.services.invoke import process_invoke, process_invoke_stream

router = APIRouter(tags=["invoke"])


# ---------------------------------------------------------------------------
# JSON mode (text query)
# ---------------------------------------------------------------------------

@router.post("/invoke")
@limiter.limit("30/minute")
async def invoke(
    request: Request,
    invoke_request: InvokeRequest,
    user: dict = Depends(get_current_user),
    stream: bool = Query(False, description="Set true to return a Server-Sent Events (SSE) stream."),
):
    """
    Process a text-only compliance query through the full D5 security pipeline.

    - **stream=false** (default): returns standard JSON InvokeResponse DTO.
    - **stream=true**: returns Server-Sent Events (text/event-stream) streaming token chunks.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    if stream:
        return StreamingResponse(
            process_invoke_stream(
                request=invoke_request,
                user=user,
                client_ip=client_ip,
                user_agent=user_agent,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return await process_invoke(
        request=invoke_request,
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# Multipart mode (file upload support)
# ---------------------------------------------------------------------------

@router.post("/invoke/file")
@limiter.limit("10/minute")
async def invoke_with_file(
    request: Request,
    user: Annotated[dict, Depends(get_current_user)],
    input: Annotated[str, Form(description="The user's query about the uploaded file.")] = ...,
    context: Annotated[str, Form(description="JSON-encoded context dict (consent, org, clinician_id, etc.)")] = "{}",
    client_trace_id: Annotated[str | None, Form()] = None,
    file: Annotated[UploadFile | None, File(description="CSV, PDF, PNG or JPG file.")] = None,
    stream: bool = Query(False, description="Set true to return a Server-Sent Events (SSE) stream."),
):
    """
    Process a compliance query that includes a file attachment.

    - **stream=false** (default): returns standard JSON InvokeResponse DTO.
    - **stream=true**: returns Server-Sent Events (text/event-stream) streaming token chunks.

    Allowed file types: CSV, PDF, PNG (screenshot), JPG (screenshot)
    Max file size: 10 MB
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    try:
        context_dict: dict = json.loads(context) if context.strip() else {}
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=422,
            content={"detail": "context field must be valid JSON."},
        )

    invoke_request = InvokeRequest(
        input=input,
        context=context_dict,
        client_trace_id=client_trace_id,
    )

    file_payload: dict | None = None
    if file is not None:
        raw_bytes = await file.read()
        filename = file.filename or "upload"
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        mime = file.content_type or "application/octet-stream"
        file_payload = {
            "filename": filename,
            "extension": ext,
            "mime": mime,
            "size_bytes": len(raw_bytes),
            "raw_bytes": raw_bytes,
        }

    if stream:
        return StreamingResponse(
            process_invoke_stream(
                request=invoke_request,
                user=user,
                client_ip=client_ip,
                user_agent=user_agent,
                file_payload=file_payload,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return await process_invoke(
        request=invoke_request,
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
        file_payload=file_payload,
    )
