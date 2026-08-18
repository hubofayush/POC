"""
app.core.guardrails.egress.layer4_wordlist
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress Layer 4 – Profanity Mask Guard (FM responses).

Masks blocked words in LLM output with "[FILTERED]" and writes the result to
context["_filtered_output"] (same contract as RoleBasedOutputFilterGuard).
Never blocks the response — masking preserves the answer.

Masks the raw output BEFORE PHI masking so the masker's character offsets
stay aligned with the original text.
"""
from __future__ import annotations

import re
from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.guardrails.wordlist import get_blocked_words
from app.core.logging import get_logger

logger = get_logger(__name__)


class ProfanityMaskGuard(BaseGuardrail):
    """
    Masks blocked words in FM output with [FILTERED].

    Always passes — it only transforms text, writing the masked output to
    context["_filtered_output"] (same contract as RoleBasedOutputFilterGuard).
    """
    name = "profanity_mask"

    def __init__(self) -> None:
        self.words = get_blocked_words()

    def mask(self, text: str) -> tuple[str, list[str]]:
        """Return (masked_text, words_found)."""
        if not settings.GUARDRAIL_WORD_FILTER_ENABLED:
            return text, []
        found = [
            w for w in self.words
            if re.search(rf"\b{re.escape(w)}\b", text, re.IGNORECASE)
        ]
        if not found:
            return text, []
        for word in found:
            text = re.sub(
                rf"\b{re.escape(word)}\b", "[FILTERED]", text,
                flags=re.IGNORECASE,
            )
        return text, found

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        # Chain on any earlier transformer output (role-based redaction)
        source = context.get("_filtered_output", input_text)
        masked, found = self.mask(source)
        if found:
            context["_filtered_output"] = masked
            logger.warning(
                "guardrail.egress.profanity_mask",
                user_id=user.get("sub"),
                blocked_words=found,
            )
            return GuardrailResult(
                passed=True,
                code="EGRESS_PROFANITY_MASKED",
                message="Blocked words masked in output.",
                layer="egress.layer4.profanity_mask",
                details={"blocked_words": found},
            )
        return PASS