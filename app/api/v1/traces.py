from fastapi import APIRouter, Depends, HTTPException, Query
from app.dependencies import require_roles
from app.core.tracing import tracer

router = APIRouter(prefix="/traces", tags=["traces"])

@router.get("")
async def list_traces(limit:int = Query(10, le=100), user:dict= Depends(require_roles(["admin","compliance_officer"]))):
    traces = tracer.get_traces(limit=limit)
    return {
        "traces":traces
    }

@router.get("/{trace_id}")
async def get_trace(trace_id:str,user:dict = Depends(require_roles(["admin","compliance_officer"]))):
    trace = tracer.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404,detail="Trace not found")
    return trace
