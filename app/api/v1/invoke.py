"""
app.api.v1.invoke
~~~~~~~~~~~~~~~~~
HTTP API Route handler for /invoke.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import get_current_user
from app.middleware.rate_limit import limiter
from app.schemas import InvokeRequest, InvokeResponse
from app.services.invoke import process_invoke

router = APIRouter(tags=["invoke"])


@router.post("/invoke", response_model=InvokeResponse)
@limiter.limit("30/minute")
async def invoke(
    request: Request,
    invoke_request: InvokeRequest,
    user: dict = Depends(get_current_user),
):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    return await process_invoke(
        request=invoke_request,
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
    )
