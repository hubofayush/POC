"""
app.api.v1.audit
~~~~~~~~~~~~~~~~
HTTP Router for Audit Log query and stats endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from app.api.deps import require_roles
from app.core.audit import query_entries, get_stats

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs")
async def list_logs(
    user_id: str | None = Query(None),
    user_org: str | None = Query(None),
    client_ip: str | None = Query(None),
    action: str | None = Query(None),
    guardrail_code: str | None = Query(None),
    guardrail_layer: str | None = Query(None),
    status: str | None = Query(None),
    resource_id: str | None = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    user: dict = Depends(require_roles(["admin", "compliance_officer"])),
):
    entries = await query_entries(
        user_id=user_id,
        user_org=user_org,
        client_ip=client_ip,
        action=action,
        guardrail_code=guardrail_code,
        guardrail_layer=guardrail_layer,
        status=status,
        resource_id=resource_id,
        limit=limit,
        offset=offset,
    )
    return {"total": len(entries), "entries": entries}


@router.get("/stats")
async def audit_stats(
    user: dict = Depends(require_roles(["admin", "compliance_officer"])),
):
    return await get_stats()