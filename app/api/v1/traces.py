from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import require_org_scope, require_roles
from app.core.tracing import tracer

router = APIRouter(prefix="/traces", tags=["traces"])


@router.get("")
async def list_traces(
    limit: int = Query(10, le=100),
    user: dict = Depends(require_roles(["admin", "compliance_officer"])),
):
    return {"traces": await tracer.get_traces(limit=limit, org=require_org_scope(user))}


@router.get("/{trace_id}")
async def get_trace(
    trace_id: str,
    user: dict = Depends(require_roles(["admin", "compliance_officer"])),
):
    trace = await tracer.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="Trace not found")
    scope_org = require_org_scope(user)
    if scope_org and trace.get("org") != scope_org:
        raise HTTPException(status_code=404, detail="Trace not found")
    return trace
