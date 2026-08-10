"""
app.schemas.responses
~~~~~~~~~~~~~~~~~~~~~
Pydantic Response DTO models.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Citation(BaseModel):
    """Structured citation metadata model."""
    file_name: str = Field(..., description="File name of source document")
    page: int | str | None = Field(None, description="Page number or range in the document")
    chunk_id: str | None = Field(None, description="Chunk ID or chunk identifier")
    chunk_name: str | None = Field(None, description="Alternative chunk name identifier")
    text: str | None = Field(None, description="Optional text snippet from the chunk")


class InvokeResponse(BaseModel):
    output: str
    citations: list[Citation | dict[str, Any] | str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
