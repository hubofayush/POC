"""
app.schemas.responses
~~~~~~~~~~~~~~~~~~~~~
Pydantic Response DTO models.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class InvokeResponse(BaseModel):
    output: str
    citations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
