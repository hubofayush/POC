"""
app.repositories
~~~~~~~~~~~~~~~~
Data Access Objects (DAOs) and Repositories for Database ORM abstraction.
"""
from app.repositories.audit_repository import AuditRepository, audit_repository

__all__ = ["audit_repository", "AuditRepository"]
