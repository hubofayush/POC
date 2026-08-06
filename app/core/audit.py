"""
app.core.audit
~~~~~~~~~~~~~~
Core audit logging interface.

Delegates persistence, SHA-256 hash calculation, and queries to app.repositories.audit_repository.
"""
from __future__ import annotations

from typing import Any, Sequence
from app.models.database import AuditEntry
from app.repositories.audit_repository import audit_repository


async def log_entry(
    user_id: str,
    user_role: str,
    action: str,
    user_org: str = "unknown",
    client_ip: str = "unknown",
    user_agent: str = "unknown",
    request_path: str = "/invoke",
    http_method: str = "POST",
    latency_ms: float = 0.0,
    input_bytes: int = 0,
    resource_type: str = "unknown",
    resource_id: str = "unknown",
    guardrail_code: str = "",
    guardrail_layer: str = "",
    phi_accessed: bool = False,
    status: str = "success",
    trace_id: str = "",
    details: str = "",
) -> str:
    """Log an audit entry via AuditRepository."""
    return await audit_repository.create_entry(
        user_id=user_id,
        user_role=user_role,
        user_org=user_org,
        client_ip=client_ip,
        user_agent=user_agent,
        request_path=request_path,
        http_method=http_method,
        latency_ms=latency_ms,
        input_bytes=input_bytes,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        guardrail_code=guardrail_code,
        guardrail_layer=guardrail_layer,
        phi_accessed=phi_accessed,
        status=status,
        trace_id=trace_id,
        details=details,
    )


async def log_guardrail_event(
    user_id: str,
    user_role: str,
    trace_id: str,
    guardrail_layer: str,
    guardrail_code: str,
    passed: bool,
    user_org: str = "unknown",
    client_ip: str = "unknown",
    user_agent: str = "unknown",
    latency_ms: float = 0.0,
    input_bytes: int = 0,
    details: str = "",
) -> str:
    """Persist a rich guardrail evaluation event to the audit log."""
    return await log_entry(
        user_id=user_id,
        user_role=user_role,
        user_org=user_org,
        client_ip=client_ip,
        user_agent=user_agent,
        request_path="/invoke",
        http_method="POST",
        latency_ms=latency_ms,
        input_bytes=input_bytes,
        action="guardrail_check",
        resource_type="ingress",
        resource_id=guardrail_layer,
        guardrail_code=guardrail_code,
        guardrail_layer=guardrail_layer,
        phi_accessed=False,
        status="pass" if passed else "block",
        trace_id=trace_id,
        details=details,
    )


async def query_entries(
    user_id: str | None = None,
    user_org: str | None = None,
    client_ip: str | None = None,
    action: str | None = None,
    guardrail_code: str | None = None,
    guardrail_layer: str | None = None,
    status: str | None = None,
    resource_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[AuditEntry]:
    """Query audit log entries via AuditRepository."""
    return await audit_repository.find_entries(
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


async def get_stats(org: str | None = None) -> dict[str, Any]:
    """Get audit summary statistics via AuditRepository (optionally org-scoped)."""
    return await audit_repository.get_summary_stats(org=org)


async def verify_chain() -> dict[str, Any]:
    """Replay the audit hash chain and report integrity."""
    return await audit_repository.verify_chain()
