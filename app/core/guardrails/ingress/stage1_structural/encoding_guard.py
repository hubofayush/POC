"""
stage1_structural.encoding_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects BiDi override chars, invisible Unicode clusters, and heavy escape sequences.
"""
from __future__ import annotations

import re
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_HEAVY_ESCAPE_RE = re.compile(
    r"(?:"
    r"(?:\\u[0-9a-fA-F]{4}){5,}"     # 5+ consecutive \uXXXX escapes
    r"|(?:&#\d{2,5};){5,}"            # 5+ consecutive HTML decimal entities
    r"|(?:%[0-9a-fA-F]{2}){10,}"      # 10+ consecutive URL-percent-encoded chars
    r")"
)
_INVISIBLE_BLOCK_RE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFFF9-\uFFFF]{3,}")
_BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")


class EncodingAnomalyGuard(BaseGuardrail):
    """
    Detects Unicode/HTML/URL escape evasion and bidirectional override attacks.
    Treats the presence of these patterns as a red flag — does NOT decode content.
    """
    name = "encoding_anomaly"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if _HEAVY_ESCAPE_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="ENCODING_ANOMALY",
                message="Input contains heavily escaped sequences indicative of an evasion attempt.",
                layer="ingress.stage1.encoding_anomaly",
                details={"reason": "heavy_escape_sequence"},
            )
        if _INVISIBLE_BLOCK_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="ENCODING_ANOMALY",
                message="Input contains clusters of invisible Unicode characters.",
                layer="ingress.stage1.encoding_anomaly",
                details={"reason": "invisible_character_cluster"},
            )
        if _BIDI_OVERRIDE_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="ENCODING_ANOMALY",
                message="Input contains bidirectional override characters used to conceal content.",
                layer="ingress.stage1.encoding_anomaly",
                details={"reason": "bidi_override_character"},
            )
        return PASS
