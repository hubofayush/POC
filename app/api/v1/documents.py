"""
app.api.v1.documents
~~~~~~~~~~~~~~~~~~~~~
Tenant-scoped Document listing and retrieval endpoints.

Tenant isolation rules:
  - Non-admin callers only see documents belonging to their own org.
  - Attempting to fetch a document from a different org returns 404 (not 403)
    to avoid leaking document existence across org boundaries.
  - Admins may query any org's documents explicitly via the `org` query parameter.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_current_user, require_roles
from app.core.security.rbac import _CROSS_ORG_ROLES, require_org_scope
from app.repositories.document_repository import document_repository

router = APIRouter(prefix="/documents", tags=["documents"])


@router.get("")
async def list_documents(
    org: str | None = Query(None, description="Org filter (admin only)"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_roles(["admin", "compliance_officer", "clinician", "hr"])),
):
    """
    List document records scoped to the caller's organisation.

    Admins may optionally pass an `org` query parameter to view another
    org's documents. Non-admin callers always see only their own org's documents.
    """
    scope_org = require_org_scope(user)

    if scope_org:
        # Non-admin: always locked to own org, ignore any `org` param
        effective_org = scope_org
    else:
        # Admin: use provided `org` filter, or None to list all
        effective_org = org

    if effective_org:
        docs = await document_repository.list_by_org(
            org=effective_org, limit=limit, offset=offset
        )
    else:
        # Admin listing all orgs — return empty for now; extend if needed
        docs = []

    return {
        "org": effective_org,
        "total": len(docs),
        "documents": [document_repository.to_dict(d) for d in docs],
    }


@router.get("/{doc_id}")
async def get_document(
    doc_id: str,
    user: dict = Depends(get_current_user),
):
    """
    Retrieve a single document record by ID.

    Returns 404 for documents belonging to other orgs — intentionally indistinguishable
    from a truly missing document to avoid cross-tenant existence leakage.
    """
    doc = await document_repository.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Tenant isolation: non-admin users cannot see docs from other orgs
    user_role = user.get("role", "")
    if user_role not in _CROSS_ORG_ROLES:
        user_org = user.get("org", "")
        if doc.org != user_org:
            # Return 404, not 403 — do not leak that the document exists
            raise HTTPException(status_code=404, detail="Document not found")

    return document_repository.to_dict(doc)
