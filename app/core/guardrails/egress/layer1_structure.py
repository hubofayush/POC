"""
app.core.guardrails.egress.layer1_structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress Layer 1 – Output Structural Integrity Guards

Operates on the raw LLM response text before any business logic runs.
These are the cheapest guards and catch the largest failure classes.

Guards (in execution order):
  1. OutputSizeLimitGuard      – hard ceiling on raw UTF-8 byte length of output
  2. OutputEncodingAnomalyGuard – detects bidi overrides and invisible-char clusters
                                  injected by the model into its own output
"""
from __future__ import annotations

import re
from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

# ---------------------------------------------------------------------------
# 1. Output Size Limit
# ---------------------------------------------------------------------------

class OutputSizeLimitGuard(BaseGuardrail):
    """
    Rejects LLM outputs whose UTF-8 encoded size exceeds GUARDRAIL_MAX_OUTPUT_BYTES.

    An abnormally large output can indicate:
    - The model was manipulated into dumping its entire context window.
    - A token-stuffing / data exfiltration attempt via the model response.
    - A runaway generation that will cause downstream parsing failures.

    Uses byte count (not char count) so that multi-byte Unicode content is
    correctly measured, preventing evasion via dense CJK / emoji payloads.
    """
    name = "output_size_limit"

    def __init__(self, max_bytes: int | None = None) -> None:
        self._max = max_bytes or settings.GUARDRAIL_MAX_OUTPUT_BYTES

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        encoded_len = len(input_text.encode("utf-8"))
        if encoded_len > self._max:
            return GuardrailResult(
                passed=False,
                code="OUTPUT_TOO_LARGE",
                message=(
                    f"LLM output exceeds maximum allowed size "
                    f"({encoded_len:,} bytes > {self._max:,} bytes limit). "
                    "Response suppressed."
                ),
                layer="egress.layer1.output_size_limit",
                details={"actual_bytes": encoded_len, "max_bytes": self._max},
            )
        return PASS


# ---------------------------------------------------------------------------
# 2. Output Encoding Anomaly Guard
# ---------------------------------------------------------------------------

# Bidi override / isolate characters — used for visual spoofing
_BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# Dense clusters of invisible / zero-width characters in the output
_INVISIBLE_BLOCK_RE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFFF9-\uFFFF]{3,}")

# Suspiciously heavy Unicode/HTML/URL escape sequences (model-generated steganography)
_HEAVY_ESCAPE_RE = re.compile(
    r"(?:"
    r"(?:\\u[0-9a-fA-F]{4}){5,}"    # 5+ consecutive \uXXXX escapes
    r"|(?:&#\d{2,5};){5,}"           # 5+ consecutive HTML decimal entities
    r"|(?:%[0-9a-fA-F]{2}){10,}"     # 10+ consecutive URL-percent-encoded chars
    r")"
)


class OutputEncodingAnomalyGuard(BaseGuardrail):
    """
    Detects bidi override characters and invisible-character clusters in
    the LLM's *output* text.

    These can appear when:
    - A prompt-injection attack caused the model to embed invisible instructions
      inside the response for a downstream consumer to 'execute'.
    - The model reproduced content that contains visual spoofing (e.g. a filename
      that looks safe but contains a bidi-reversed extension).
    - Model-generated steganography (encoding data in zero-width chars).

    Note: some legitimate outputs may contain individual bidi marks (e.g. Arabic
    names in a healthcare record). The guard triggers only on *clusters* or
    *override* characters, not isolated directional marks.
    """
    name = "output_encoding_anomaly"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if _BIDI_OVERRIDE_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="OUTPUT_ENCODING_ANOMALY",
                message=(
                    "LLM output contains bidirectional override characters that can "
                    "be used for visual spoofing or to conceal injected instructions."
                ),
                layer="egress.layer1.output_encoding_anomaly",
                details={"reason": "bidi_override_character"},
            )
        if _INVISIBLE_BLOCK_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="OUTPUT_ENCODING_ANOMALY",
                message=(
                    "LLM output contains clusters of invisible Unicode characters "
                    "indicative of model-generated steganography or injection."
                ),
                layer="egress.layer1.output_encoding_anomaly",
                details={"reason": "invisible_character_cluster"},
            )
        if _HEAVY_ESCAPE_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="OUTPUT_ENCODING_ANOMALY",
                message=(
                    "LLM output contains heavily escaped Unicode/HTML/URL sequences "
                    "that may encode hidden instructions."
                ),
                layer="egress.layer1.output_encoding_anomaly",
                details={"reason": "heavy_escape_sequence"},
            )
        return PASS
