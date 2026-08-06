"""
app.repositories.audit_repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Data Access Object (DAO) / Repository encapsulating database operations
for Production-Grade Audit Log entities.

Computes SHA-256 tamper-evident checksums for every audit entry.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import uuid4
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AuditEntry, async_session

# Serializes audit inserts so the hash chain can never fork. Single-process
# POC assumption; a Postgres advisory lock or sequence-based prev_hash is the
# distributed equivalent.
_chain_lock = asyncio.Lock()


def _canonical_ts(ts: datetime) -> str:
    """Normalize a (possibly aware) datetime to one canonical string.

    SQLite round-trips DateTime(timezone=True) as naive text, so aware values
    must be converted to UTC before stringification or the chain breaks.
    """
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")


class AuditRepository:
    """Repository handling all audit database persistence, querying, and checksums."""

    def _compute_hash(
        self,
        prev_hash: str,
        entry_id: str,
        user_id: str,
        action: str,
        status: str,
        timestamp_str: str,
        details: str,
    ) -> str:
        """Computes the chained SHA-256 hash for an entry.

        Includes the previous entry's hash, so any modification anywhere in
        the log invalidates every subsequent entry.
        """
        raw_str = f"{prev_hash}|{entry_id}|{user_id}|{action}|{status}|{timestamp_str}|{details}"
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
        """Insert a new immutable audit record linked to the chain (prev_hash)."""
        async with _chain_lock:
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
                # Chain link: last entry's hash becomes this entry's prev_hash
                prev_hash = await session.scalar(
                    select(AuditEntry.entry_hash)
                    .order_by(desc(AuditEntry.timestamp), desc(AuditEntry.entry_id))
                    .limit(1)
                ) or ""
                entry.prev_hash = prev_hash
                # Defaults fire at flush — set id/timestamp now so the chain
                # hash is computed over the exact persisted values.
                entry.entry_id = str(uuid4())
                entry.timestamp = datetime.now(timezone.utc)
                entry.entry_hash = self._compute_hash(
                    prev_hash,
                    entry.entry_id,
                    user_id,
                    action,
                    status,
                    _canonical_ts(entry.timestamp),
                    details,
                )
                session.add(entry)
                await session.commit()
                return entry.entry_id

    async def verify_chain(self) -> dict[str, Any]:
        """Replays the hash chain and reports integrity.

        Returns:
            {"valid": bool, "entries_checked": int, "first_broken_entry_id": str | None}
        """
        async with async_session() as session:
            rows = (
                await session.execute(
                    select(AuditEntry)
                    .order_by(AuditEntry.timestamp, AuditEntry.entry_id)
                )
            ).scalars().all()

            prev_hash = ""
            for entry in rows:
                expected = self._compute_hash(
                    prev_hash,
                    entry.entry_id,
                    entry.user_id,
                    entry.action,
                    entry.status,
                    _canonical_ts(entry.timestamp),
                    entry.details,
                )
                if entry.prev_hash != prev_hash or entry.entry_hash != expected:
                    return {
                        "valid": False,
                        "entries_checked": len(rows),
                        "first_broken_entry_id": entry.entry_id,
                    }
                prev_hash = entry.entry_hash

            return {"valid": True, "entries_checked": len(rows), "first_broken_entry_id": None}

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
