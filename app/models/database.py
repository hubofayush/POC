"""
app.models.database
~~~~~~~~~~~~~~~~~~~
SQLAlchemy database models and connection engine.

AuditEntry model enforces append-only immutability via SQLAlchemy ORM event listeners.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Text, Float, Integer, event
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import settings


class Base(DeclarativeBase):
    pass


class AuditEntry(Base):
    """
    Production-Grade Audit Entry Model (SOC2 / HIPAA Compliant).

    Includes network forensics (client_ip, user_agent), tenant context (user_org),
    execution performance (latency_ms), indexed security attributes (guardrail_code,
    guardrail_layer), and SHA-256 tamper-evident hash chaining.
    """
    __tablename__ = "audit_log"

    entry_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    # User & Tenant Context
    user_id: Mapped[str] = mapped_column(String(100), index=True)
    user_role: Mapped[str] = mapped_column(String(50))
    user_org: Mapped[str] = mapped_column(String(100), index=True, default="unknown")

    # Request & Network Forensics
    client_ip: Mapped[str] = mapped_column(String(45), index=True, default="unknown")
    user_agent: Mapped[str] = mapped_column(Text, default="unknown")
    request_path: Mapped[str] = mapped_column(String(255), default="/invoke")
    http_method: Mapped[str] = mapped_column(String(10), default="POST")

    # Execution Performance & Sizing
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    input_bytes: Mapped[int] = mapped_column(Integer, default=0)
    phi_accessed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Security & Guardrail Specifics
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(100), default="unknown")
    resource_id: Mapped[str] = mapped_column(String(100), default="unknown", index=True)
    guardrail_code: Mapped[str] = mapped_column(String(100), index=True, default="")
    guardrail_layer: Mapped[str] = mapped_column(String(100), index=True, default="")
    status: Mapped[str] = mapped_column(String(20), index=True, default="success")

    # Tracing, Structured Details & Cryptographic Hash
    trace_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    details: Mapped[str] = mapped_column(Text, default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="")


# ── Database Immutability Event Listeners ────────────────────────────────────
# Prevents UPDATE or DELETE on AuditEntry to enforce tamper-proof audit trails

@event.listens_for(AuditEntry, "before_update")
def _prevent_audit_update(mapper, connection, target):
    raise PermissionError("Audit log entries are immutable and cannot be updated.")


@event.listens_for(AuditEntry, "before_delete")
def _prevent_audit_delete(mapper, connection, target):
    raise PermissionError("Audit log entries are immutable and cannot be deleted.")


engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)