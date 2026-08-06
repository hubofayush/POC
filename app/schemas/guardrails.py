"""
app.schemas.guardrails
~~~~~~~~~~~~~~~~~~~~~~
Pydantic schemas for guardrail violation error responses (RFC 9457).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GuardrailViolation(BaseModel):
    """
    Structured response body returned when a guardrail blocks a request.
    Follows RFC 9457 Problem Details + guardrail-specific extensions.
    """
    type: str = "https://tools.ietf.org/html/rfc9457"
    title: str = "Request Blocked by Guardrail"
    status: int
    detail: str
    instance: str
    extensions: dict[str, Any] = Field(default_factory=dict)
