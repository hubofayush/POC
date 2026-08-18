"""
stage2_threat.encoded_payload_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects base64 and hex-encoded attack payloads smuggled in user input.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_SUSPICIOUS_DECODED = re.compile(
    r"(?:ignore|override|forget|bypass|system\s+prompt|jailbreak|do\s+anything|reveal|dump)",
    re.IGNORECASE,
)
_HEX_PAYLOAD_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){20,}\b")


class EncodedPayloadGuard(BaseGuardrail):
    """Detects base64 or hex-encoded attack payloads."""
    name = "encoded_payload"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        for match in _B64_RE.finditer(input_text):
            candidate = match.group()
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if _SUSPICIOUS_DECODED.search(decoded):
                    return GuardrailResult(
                        passed=False,
                        code="ENCODED_PAYLOAD_DETECTED",
                        message="Request rejected: base64-encoded suspicious instruction detected.",
                        layer="ingress.stage2.encoded_payload",
                        details={"encoding": "base64", "decoded_preview": decoded[:80]},
                    )
            except (binascii.Error, UnicodeDecodeError):
                pass

        if settings.GUARDRAIL_ENCODED_PAYLOAD_BLOCK:
            for match in _HEX_PAYLOAD_RE.finditer(input_text):
                candidate = match.group()
                try:
                    decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
                    if _SUSPICIOUS_DECODED.search(decoded):
                        return GuardrailResult(
                            passed=False,
                            code="ENCODED_PAYLOAD_DETECTED",
                            message="Request rejected: hex-encoded suspicious instruction detected.",
                            layer="ingress.stage2.encoded_payload",
                            details={"encoding": "hex", "decoded_preview": decoded[:80]},
                        )
                except ValueError:
                    pass
        return PASS
