"""
app.repositories
~~~~~~~~~~~~~~~~
Data Access Objects (DAOs) and Repositories for Database ORM abstraction.
"""
from app.repositories.audit_repository import audit_repository, AuditRepository

__all__ = ["audit_repository", "AuditRepository"]
