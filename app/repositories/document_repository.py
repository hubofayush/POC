"""
app.repositories.document_repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Data Access Object for Document upload records.

Handles create, status update, and retrieval of document metadata
persisted on every file upload that passes D5 guardrails.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import desc, select

from app.models.database import Document, async_session


class DocumentRepository:
    """Repository for Document persistence and querying."""

    async def create(
        self,
        uploader_id: str,
        org: str,
        filename: str,
        file_type: str,
        file_size_bytes: int,
        trace_id: str = "",
    ) -> str:
        """Insert a new Document record in 'pending' state. Returns doc_id."""
        async with async_session() as session:
            doc = Document(
                doc_id=str(uuid4()),
                uploader_id=uploader_id,
                org=org,
                filename=filename,
                file_type=file_type,
                file_size_bytes=file_size_bytes,
                upload_status="pending",
                guardrail_result="pending",
                trace_id=trace_id,
                uploaded_at=datetime.now(UTC),
            )
            session.add(doc)
            await session.commit()
            return doc.doc_id

    async def mark_rejected(self, doc_id: str) -> None:
        """Mark a document as rejected (guardrail blocked it)."""
        async with async_session() as session:
            doc = await session.get(Document, doc_id)
            if doc:
                doc.upload_status = "rejected"
                doc.guardrail_result = "blocked"
                await session.commit()

    async def mark_indexed(self, doc_id: str, d1_doc_id: str | None = None) -> None:
        """Mark a document as successfully indexed by D1."""
        async with async_session() as session:
            doc = await session.get(Document, doc_id)
            if doc:
                doc.upload_status = "indexed"
                doc.guardrail_result = "passed"
                doc.d1_doc_id = d1_doc_id
                await session.commit()

    async def get(self, doc_id: str) -> Document | None:
        """Retrieve a document record by ID."""
        async with async_session() as session:
            return await session.get(Document, doc_id)

    async def list_by_org(
        self,
        org: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Document]:
        """List documents for a given org, newest first."""
        async with async_session() as session:
            stmt = (
                select(Document)
                .where(Document.org == org)
                .order_by(desc(Document.uploaded_at))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    def to_dict(self, doc: Document) -> dict[str, Any]:
        """Serialize a Document ORM row to a plain dict."""
        return {
            "doc_id": doc.doc_id,
            "filename": doc.filename,
            "file_type": doc.file_type,
            "file_size_bytes": doc.file_size_bytes,
            "upload_status": doc.upload_status,
            "guardrail_result": doc.guardrail_result,
            "d1_doc_id": doc.d1_doc_id,
            "uploaded_at": doc.uploaded_at.isoformat() if doc.uploaded_at else None,
            "trace_id": doc.trace_id,
        }


document_repository = DocumentRepository()
