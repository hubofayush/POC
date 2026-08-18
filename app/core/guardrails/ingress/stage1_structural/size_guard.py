"""
stage1_structural.size_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
UTF-8 byte budget guard — rejects inputs that exceed the raw byte size ceiling.
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult


class UTF8BudgetGuard(BaseGuardrail):
    """
    Rejects inputs whose UTF-8 encoded size exceeds GUARDRAIL_MAX_INPUT_BYTES.

    Multi-byte Unicode chars (CJK, emoji) pack more semantic content per
    'character' than ASCII — keying on bytes prevents that from being exploited.
    """
    name = "utf8_budget"

    def __init__(self, max_bytes: int | None = None) -> None:
        self._max = max_bytes or settings.GUARDRAIL_MAX_INPUT_BYTES

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        encoded_len = len(input_text.encode("utf-8"))
        if encoded_len > self._max:
            return GuardrailResult(
                passed=False,
                code="INPUT_TOO_LARGE",
                message=(
                    f"Input exceeds maximum allowed size "
                    f"({encoded_len:,} bytes > {self._max:,} bytes limit)."
                ),
                layer="ingress.stage1.utf8_budget",
                details={"actual_bytes": encoded_len, "max_bytes": self._max},
            )
        return PASS
