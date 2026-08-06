"""
app.dependencies
~~~~~~~~~~~~~~~~
Proxy module re-exporting dependencies from app.api.deps for backward compatibility.
"""
from app.api.deps import get_current_user, require_roles

__all__ = ["get_current_user", "require_roles"]