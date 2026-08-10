"""
app.core.guardrails.ingress.layer2_security
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 2 – Security / Threat Detection Guards

Detects prompt injection, jailbreak, delimiter hijacking, encoded payloads,
token-flooding, and raw PHI in the input before it reaches the LLM.

Guards (in execution order):
  1. PromptInjectionGuard     – extended injection + DAN/jailbreak patterns
  2. DelimiterHijackGuard     – model-internal tag/marker injection
  3. EncodedPayloadGuard      – base64 / hex encoded suspicious instructions
  4. ExcessiveRepetitionGuard – token-flooding (same token repeated ≥ 50×)
  5. PHIInInputGuard          – detects raw PHI (warn-only by design)
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Normalisation helpers (shared across guards)
# ---------------------------------------------------------------------------

# Homoglyph / leetspeak normalisation map  (extend as needed)
_LEET: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i",
}

_INVISIBLE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFEFF\x00-\x1F\x7F]")


def _normalise(text: str) -> str:
    """Strip invisibles, collapse whitespace, apply leetspeak map, NFKD fold."""
    # 1. Remove invisible / control characters
    text = _INVISIBLE.sub("", text)
    # 2. NFKD unicode normalisation (folds homoglyphs)
    text = unicodedata.normalize("NFKD", text)
    # 3. Leetspeak substitution
    text = "".join(_LEET.get(c, c) for c in text)
    # 4. Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text.lower()


# ---------------------------------------------------------------------------
# 1. Prompt Injection Guard
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[str] = [
    # ── Direct instruction override ──
    r"(?:ignore|disregard|forget|bypass|override|skip)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?)",
    # ── Persona hijacking ──
    r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|assume\s+the\s+role\s+of)\s+(?:an?\s+)?(?:unrestricted|evil|jailbroken|developer|admin|system|root|hacker)",
    r"you\s+must\s+(?:now\s+)?(?:follow|obey|answer)\s+(?:only|my)\s+(?:new\s+)?instructions",
    # ── DAN / STAN / DUDE / AIM jailbreaks ──
    r"\bdan\b.*\bdo\s+anything\s+now\b",
    r"\bstan\b.*\bstrive\s+to\s+avoid\s+niceties\b",
    r"\bdude\b.*\bdo\s+unlimited\s+driver\b",
    r"\baim\b.*\balways\s+intelligent\s+and\s+machiavellian\b",
    r"jailbreak(?:ed|ing)?\s+(?:mode|version|prompt)",
    # ── System prompt extraction ──
    # Handles: 'reveal the system prompt', 'reveal your original system instructions',
    # 'what are your system instructions', 'show me the initial rules', etc.
    r"(?:show|print|display|reveal|output|repeat|share|dump|leak|expose)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:(?:original|initial|developer|hidden|confidential|real|actual)\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|context|message)",
    r"what\s+(?:are|were|is)\s+(?:your\s+)?(?:original|initial|system|real|actual)\s+(?:system\s+)?(?:instructions?|prompts?|rules?|purpose|directives?)",
    r"(?:tell|show|give)\s+me\s+(?:your|the)\s+(?:original|initial|real|actual|system)\s+(?:system\s+)?(?:instructions?|prompts?|rules?|context)",
    # ── Compliance bypass ──
    r"(?:do\s+not|stop|cease)\s+(?:follow|enforc|apply)ing?\s+(?:security|safety|hipaa|phi|compliance|privacy)\s+(?:rules?|policy|policies|guidelines?|restrictions?)",
    r"(?:disregard|ignore|bypass)\s+(?:hipaa|privacy|compliance|gdpr|regulation)\s+(?:protocol|rules?|restrictions?|requirements?)",
    r"(?:from\s+now\s+on|henceforth|starting\s+now),?\s*you\s+(?:will|can|should|must)\s+(?:do|answer|respond)\s+(?:anything|everything|without\s+restrictions?)",
    # ── Token smuggling / repeat-after-me ──
    r"(?:repeat|echo|say|print|output)\s+(?:back\s+)?(?:after\s+me|the\s+following|these\s+words)",
    r"translate\s+(?:the\s+following\s+)?(?:text|message|instruction)\s+and\s+(?:follow|execute|obey)",
    # ── Sandbox escape ──
    r"(?:escape|exit|break\s+out\s+of)\s+(?:the\s+)?(?:sandbox|container|restrictions?|guardrails?|limitations?)",
    r"(?:pretend|imagine|suppose|assume)\s+(?:there\s+are|you\s+have)\s+no\s+(?:restrictions?|rules?|guidelines?|limits?)",
]

_COMPILED_INJECTION = [
    re.compile(p, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    for p in _INJECTION_PATTERNS
]


class PromptInjectionGuard(BaseGuardrail):
    """
    Detects prompt injection and jailbreak attempts via normalised pattern matching.

    Applies homoglyph/leetspeak normalisation before matching to defeat
    simple character-substitution evasions (e.g. "1gnore" → "ignore").
    """
    name = "prompt_injection"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        normalised = _normalise(input_text)
        for pattern in _COMPILED_INJECTION:
            match = pattern.search(normalised)
            if match:
                return GuardrailResult(
                    passed=False,
                    code="PROMPT_INJECTION_DETECTED",
                    message="Request rejected: potential prompt injection or jailbreak attempt detected.",
                    layer="ingress.layer2.prompt_injection",
                    details={"matched_pattern": pattern.pattern[:80]},
                )
        return PASS


# ---------------------------------------------------------------------------
# 2. Delimiter Hijack Guard
# ---------------------------------------------------------------------------

_DELIMITER_PATTERNS: list[str] = [
    # OpenAI / Anthropic chat-ML delimiters
    r"<\s*/?\s*(?:system|im_start|im_end|instruction|human|assistant|user)\s*>",
    r"\|?\s*<\s*\|?\s*(?:im_start|im_end|endoftext)\s*\|?\s*>?\|?",
    # Bracket-style system markers
    r"\[\s*/?\s*(?:INST|SYS|SYSTEM|HUMAN|ASSISTANT|BEGIN|END)\s*\]",
    # Raw override headers
    r"#{1,6}\s*(?:SYSTEM|OVERRIDE|IGNORE|NEW\s+INSTRUCTION)",
    r"<<<\s*(?:SYSTEM|OVERRIDE|ADMIN|ROOT)\s*>>>",
    r"---\s*(?:SYSTEM|OVERRIDE|INSTRUCTION)\s*---",
    # Code fence injection (starting a fake system block in markdown)
    r"```\s*(?:json|xml|markdown|system|yaml)?\s*\n\s*(?:system|override|ignore|forget)",
]

_COMPILED_DELIMITERS = [
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in _DELIMITER_PATTERNS
]


class DelimiterHijackGuard(BaseGuardrail):
    """
    Detects injected model-internal delimiters that attempt to create a
    fake 'system' segment in the LLM's context window.
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
                    layer="ingress.layer2.delimiter_hijack",
                    details={"matched_pattern": pattern.pattern[:80]},
                )
        return PASS


# ---------------------------------------------------------------------------
# 3. Encoded Payload Guard
# ---------------------------------------------------------------------------

# Matches a contiguous base64-looking string of ≥ 40 chars (≥ 30 bytes decoded)
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Suspicious decoded strings that indicate an encoded instruction
_SUSPICIOUS_DECODED = re.compile(
    r"(?:ignore|override|forget|bypass|system\s+prompt|jailbreak|do\s+anything)",
    re.IGNORECASE,
)

# Dense hex sequences (≥ 20 bytes = 40 hex chars)
_HEX_PAYLOAD_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){20,}\b")


class EncodedPayloadGuard(BaseGuardrail):
    """
    Detects base64 or hex-encoded attack payloads in the input.

    Strategy:
    - Find base64 candidates of meaningful length.
    - Attempt to decode; if decoded text matches suspicious keywords, block.
    - Always block dense hex sequences (≥ 40 hex chars) when
      GUARDRAIL_ENCODED_PAYLOAD_BLOCK is True.
    """
    name = "encoded_payload"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        # --- base64 scan ---
        for match in _B64_RE.finditer(input_text):
            candidate = match.group()
            try:
                # Pad to valid length
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if _SUSPICIOUS_DECODED.search(decoded):
                    return GuardrailResult(
                        passed=False,
                        code="ENCODED_PAYLOAD_DETECTED",
                        message=(
                            "Request rejected: base64-encoded suspicious instruction detected."
                        ),
                        layer="ingress.layer2.encoded_payload",
                        details={"encoding": "base64", "decoded_preview": decoded[:80]},
                    )
            except (binascii.Error, UnicodeDecodeError):
                pass  # Not valid base64 – not a threat

        # --- hex scan ---
        if settings.GUARDRAIL_ENCODED_PAYLOAD_BLOCK:
            for match in _HEX_PAYLOAD_RE.finditer(input_text):
                candidate = match.group()
                try:
                    decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
                    if _SUSPICIOUS_DECODED.search(decoded):
                        return GuardrailResult(
                            passed=False,
                            code="ENCODED_PAYLOAD_DETECTED",
                            message=(
                                "Request rejected: hex-encoded suspicious instruction detected."
                            ),
                            layer="ingress.layer2.encoded_payload",
                            details={"encoding": "hex", "decoded_preview": decoded[:80]},
                        )
                except ValueError:
                    pass

        return PASS


# ---------------------------------------------------------------------------
# 4. Excessive Repetition Guard
# ---------------------------------------------------------------------------

# Matches any single token (word / char) repeated ≥ 50 consecutive times
_REPEAT_WORD_RE = re.compile(r"\b(\w+)\b(?:\s+\1\b){49,}", re.IGNORECASE)
_REPEAT_CHAR_RE = re.compile(r"(.)\1{99,}")  # same char 100+ times


class ExcessiveRepetitionGuard(BaseGuardrail):
    """
    Detects token-flooding attacks: same word or character repeated an
    abnormal number of times to confuse the model or overflow the context.
    """
    name = "excessive_repetition"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if _REPEAT_WORD_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="EXCESSIVE_REPETITION",
                message="Request rejected: excessive word repetition detected (token-flooding).",
                layer="ingress.layer2.excessive_repetition",
                details={"type": "word_repetition"},
            )
        if _REPEAT_CHAR_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="EXCESSIVE_REPETITION",
                message="Request rejected: excessive character repetition detected.",
                layer="ingress.layer2.excessive_repetition",
                details={"type": "char_repetition"},
            )
        return PASS


# ---------------------------------------------------------------------------
# 5. PHI-in-Input Guard  (warn only – does NOT block by default)
# ---------------------------------------------------------------------------

from app.core.phi.detector import detect_phi  # noqa: E402  (avoid circular at top-level)


class PHIInInputGuard(BaseGuardrail):
    """
    Detects raw PHI present in the user's *input* text.

    This is a warn-only guard by design: legitimate clinical queries may include
    patient identifiers.  The finding is logged for audit purposes and the
    request proceeds.  PHI will be masked before it reaches the LLM via the
    existing mask_phi() pipeline in services/invoke.py.
    """
    name = "phi_in_input"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        findings = detect_phi(input_text)
        if findings:
            types_found = list({f.type for f in findings})
            logger.warning(
                "guardrail.phi_in_input",
                phi_types=types_found,
                count=len(findings),
                user_id=user.get("sub"),
            )
            # Warn-only: return PASS with note in details
            return GuardrailResult(
                passed=True,
                code="PHI_IN_INPUT_WARNED",
                message="Raw PHI detected in input; proceeding with masking pipeline.",
                layer="ingress.layer2.phi_in_input",
                details={"phi_types": types_found, "count": len(findings)},
            )
        return PASS
