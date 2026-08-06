"""
app.repositories.audit_repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Data Access Object (DAO) / Repository encapsulating database operations
for Production-Grade Audit Log entities.

Computes SHA-256 tamper-evident checksums for every audit entry.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AuditEntry, async_session


class AuditRepository:
    """Repository handling all audit database persistence, querying, and checksums."""

    def _compute_hash(
        self,
        entry_id: str,
        user_id: str,
        action: str,
        status: str,
        timestamp_str: str,
        details: str,
    ) -> str:
        """Computes a SHA-256 hash string for entry tamper detection."""
        raw_str = f"{entry_id}|{user_id}|{action}|{status}|{timestamp_str}|{details}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    async def create_entry(
        self,
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
        """Insert a new immutable audit record with computed SHA-256 entry_hash."""
        async with async_session() as session:
            entry = AuditEntry(
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
            # Compute cryptographic entry hash
            entry.entry_hash = self._compute_hash(
                entry.entry_id, user_id, action, status, str(entry.timestamp), details
            )
            session.add(entry)
            await session.commit()
            return entry.entry_id

    async def find_entries(
        self,
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
        """Query audit log entries with advanced filtering and pagination."""
        async with async_session() as session:
            stmt = select(AuditEntry)
            if user_id:
                stmt = stmt.where(AuditEntry.user_id == user_id)
            if user_org:
                stmt = stmt.where(AuditEntry.user_org == user_org)
            if client_ip:
                stmt = stmt.where(AuditEntry.client_ip == client_ip)
            if action:
                stmt = stmt.where(AuditEntry.action == action)
            if guardrail_code:
                stmt = stmt.where(AuditEntry.guardrail_code == guardrail_code)
            if guardrail_layer:
                stmt = stmt.where(AuditEntry.guardrail_layer == guardrail_layer)
            if status:
                stmt = stmt.where(AuditEntry.status == status)
            if resource_id:
                stmt = stmt.where(AuditEntry.resource_id == resource_id)

            stmt = stmt.order_by(desc(AuditEntry.timestamp)).limit(limit).offset(offset)
            result = await session.execute(stmt)
            return result.scalars().all()

    async def get_summary_stats(self, org: str | None = None) -> dict[str, Any]:
        """Calculate production-grade audit summary statistics (optionally org-scoped)."""
        org_filter = (AuditEntry.user_org == org,) if org else ()

        async with async_session() as session:
            total = await session.scalar(
                select(func.count(AuditEntry.entry_id)).where(*org_filter)
            )
            success = await session.scalar(
                select(func.count(AuditEntry.entry_id)).where(
                    AuditEntry.status == "success", *org_filter
                )
            )
            blocked = await session.scalar(
                select(func.count(AuditEntry.entry_id)).where(
                    AuditEntry.status == "block", *org_filter
                )
            )
            phi = await session.scalar(
                select(func.count(AuditEntry.entry_id)).where(
                    AuditEntry.phi_accessed == True, *org_filter
                )
            )
            avg_latency = await session.scalar(
                select(func.avg(AuditEntry.latency_ms)).where(*org_filter)
            ) or 0.0

            return {
                "total_entries": total or 0,
                "success_count": success or 0,
                "blocked_guardrails": blocked or 0,
                "success_rate": f"{(success / total * 100):.1f}%" if total else "N/A",
                "phi_accesses": phi or 0,
                "avg_latency_ms": round(float(avg_latency), 2),
            }


audit_repository = AuditRepository()
