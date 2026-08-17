"""
app.core.guardrails.ingress.layer2_wordlist
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 2 – Word Filter Guard (profanity / banned words on user input).

Blocks requests containing blocked words. A word-list check is cheap and
runs early (Layer 2) alongside the security guards.

Mode is controlled by settings.GUARDRAIL_MODERATION_MODE (shared "block"/"warn"
semantics for content-style guards): default "block".
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.guardrails.wordlist import find_blocked_words
from app.core.logging import get_logger

logger = get_logger(__name__)


class WordFilterGuard(BaseGuardrail):
    """
    Blocks user input containing profanity / blocked words.

    Curated default set lives in app.core.guardrails.wordlist; extend via
    settings.GUARDRAIL_WORD_FILTER_WORDS (comma-separated).
    """
    name = "word_filter"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if not settings.GUARDRAIL_WORD_FILTER_ENABLED:
            return PASS

        found = find_blocked_words(input_text)
        if not found:
            return PASS

        details = {"blocked_words": found}
        if settings.GUARDRAIL_MODERATION_MODE == "block":
            return GuardrailResult(
                passed=False,
                code="BLOCKED_WORD_IN_INPUT",
                message="Request rejected: input contains blocked language.",
                layer="ingress.layer2.word_filter",
                details=details,
            )
        logger.warning("guardrail.word_filter.warn", user_id=user.get("sub"), **details)
        return GuardrailResult(
            passed=True,
            code="BLOCKED_WORD_WARNED",
            message="Input contains blocked language (warning only).",
            layer="ingress.layer2.word_filter",
            details=details,
        )