"""
app.schemas.requests
~~~~~~~~~~~~~~~~~~~~
Pydantic Request DTO models with Layer 1 field validation rules.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

# Prototype-pollution keys blocked at schema level
_FORBIDDEN_CONTEXT_KEYS: frozenset[str] = frozenset(
    ["__proto__", "constructor", "prototype", "__class__", "__import__"]
)


class InvokeRequest(BaseModel):
    input: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="The user's query or instruction to be processed.",
        examples=["Is nurse John Doe's RN license current?"],
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured context carrying session metadata (consent, clinician IDs, etc.)",
    )
    client_trace_id: str | None = Field(
        default=None,
        max_length=64,
        description="Optional caller-supplied correlation ID for end-to-end tracing.",
    )

    @field_validator("input", mode="before")
    @classmethod
    def strip_and_validate_input(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError("input must be a string")
        stripped = v.strip()
        if not stripped:
            raise ValueError("input must not be blank or whitespace-only")
        if "\x00" in stripped:
            raise ValueError("input must not contain null bytes")
        return stripped

    @field_validator("context", mode="before")
    @classmethod
    def validate_context(cls, v: Any) -> dict:
        if not isinstance(v, dict):
            raise ValueError("context must be a JSON object")
        for key in v:
            if key in _FORBIDDEN_CONTEXT_KEYS:
                raise ValueError(
                    f"context contains forbidden key '{key}' "
                    f"(prototype-pollution guard)"
                )
        return v
