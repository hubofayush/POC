"""
stage2_threat.delimiter_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects model-internal delimiter injection (ChatML, bracket markers, markdown code fences).
"""
from __future__ import annotations

import re
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_DELIMITER_PATTERNS: list[str] = [
    # OpenAI / Anthropic ChatML delimiters
    r"<\s*/?s*(?:system|im_start|im_end|instruction|human|assistant|user)\s*>",
    r"\|?\s*<\s*\|?\s*(?:im_start|im_end|endoftext)\s*\|?\s*>?\|?",
    # Bracket-style system markers
    r"\[\s*/?s*(?:INST|SYS|SYSTEM|HUMAN|ASSISTANT|BEGIN|END)\s*\]",
    # Raw override headers
    r"#{1,6}\s*(?:SYSTEM|OVERRIDE|IGNORE|NEW\s+INSTRUCTION)",
    r"<<<\s*(?:SYSTEM|OVERRIDE|ADMIN|ROOT)\s*>>>",
    r"---\s*(?:SYSTEM|OVERRIDE|INSTRUCTION)\s*---",
    # Code fence injection (fake system block in markdown)
    r"```\s*(?:json|xml|markdown|system|yaml)?\s*\n\s*(?:system|override|ignore|forget)",
    # XML-style instruction wrapping
    r"<(?:instruction|system|prompt|context|override)>",
    r"</?(?:SYSTEM|INSTRUCTION|PROMPT|CONTEXT)>",
]

_COMPILED_DELIMITERS = [
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in _DELIMITER_PATTERNS
]


class DelimiterHijackGuard(BaseGuardrail):
    """
    Blocks injected model-internal delimiters that create a fake 'system' segment
    in the LLM's context window.
    """
    name = "delimiter_hijack"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        for pattern in _COMPILED_DELIMITERS:
            if pattern.search(input_text):
                return GuardrailResult(
                    passed=False,
                    code="DELIMITER_HIJACK_DETECTED",
                    message="Request rejected: model delimiter injection detected in input.",
                    layer="ingress.stage2.delimiter_hijack",
                    details={"matched_pattern": pattern.pattern[:80]},
                )
        return PASS
