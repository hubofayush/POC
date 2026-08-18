"""
stage2_threat.repetition_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects token-flooding attacks: same word or character repeated an abnormal number of times.
"""
from __future__ import annotations

import re
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_REPEAT_WORD_RE = re.compile(r"\b(\w+)\b(?:\s+\1\b){49,}", re.IGNORECASE)
_REPEAT_CHAR_RE = re.compile(r"(.)\1{99,}")


class ExcessiveRepetitionGuard(BaseGuardrail):
    """Blocks same-word (≥50×) and same-character (≥100×) repetition attacks."""
    name = "excessive_repetition"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if _REPEAT_WORD_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="EXCESSIVE_REPETITION",
                message="Request rejected: excessive word repetition detected (token-flooding).",
                layer="ingress.stage2.excessive_repetition",
                details={"type": "word_repetition"},
            )
        if _REPEAT_CHAR_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="EXCESSIVE_REPETITION",
                message="Request rejected: excessive character repetition detected.",
                layer="ingress.stage2.excessive_repetition",
                details={"type": "char_repetition"},
            )
        return PASS
