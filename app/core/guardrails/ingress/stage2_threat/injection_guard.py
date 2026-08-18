"""
stage2_threat.injection_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Production-grade prompt injection detection with 3-pass matching:

  Pass 1 — Normalise (NFKD + leetspeak + invisible strip)
  Pass 2 — Fuzzy trigger-word detection via rapidfuzz edit-distance
            Catches: ignroe, bypaas, 0verride, forGET (≤1 edit from trigger)
  Pass 3 — Expanded regex on normalised text (multi-clause, typo-tolerant patterns)

This triple-pass ensures attacks using typos, character substitutions,
or unusual spacing are caught regardless of which evasion technique is used.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from rapidfuzz.distance import DamerauLevenshtein

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Pass 1 — Normalization
# ---------------------------------------------------------------------------

_LEET: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "€": "e",
}
_INVISIBLE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFEFF\x00-\x1F\x7F]")


def _normalise(text: str) -> str:
    """Strip invisibles, NFKD fold, apply leet map, collapse whitespace."""
    text = _INVISIBLE.sub("", text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(_LEET.get(c, c) for c in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.lower()


# ---------------------------------------------------------------------------
# Pass 2 — Fuzzy trigger-word & attack vocabulary correction (Damerau-Levenshtein)
# ---------------------------------------------------------------------------

# Critical attack trigger words — verb/action words that drive injection attacks
_INJECTION_TRIGGERS: frozenset[str] = frozenset([
    "ignore", "disregard", "forget", "bypass", "override", "skip",
    "pretend", "jailbreak", "escape", "reveal", "dump", "leak",
    "translate", "impersonate", "assume", "imagine",
])

# Key attack nouns — objects that appear alongside trigger verbs in injection patterns
_INJECTION_NOUNS: frozenset[str] = frozenset([
    "prompts", "instructions", "rules", "directives", "guidelines",
    "system", "previous", "context", "configuration", "restrictions",
    "filters", "safety", "constraints", "boundaries", "policies",
])

# Combined vocabulary for fuzzy correction (both verbs and nouns)
_FUZZY_VOCAB: frozenset[str] = _INJECTION_TRIGGERS | _INJECTION_NOUNS

# Minimum token length to apply fuzzy matching
_MIN_FUZZY_LEN = 4


def _fuzzy_correct_text(normalised_text: str, threshold: int = 1) -> tuple[str, bool]:
    """
    Applies fuzzy correction to all tokens in the normalised text using Damerau-Levenshtein
    distance (which correctly handles character transpositions like 'ignroe' -> 'ignore' as dist 1).

    Returns (corrected_text, was_modified).
    """
    tokens = re.findall(r"\b\w+\b", normalised_text)
    corrections: dict[str, str] = {}

    for token in tokens:
        if len(token) < _MIN_FUZZY_LEN or token in corrections or token in _FUZZY_VOCAB:
            continue
        best_vocab_word = None
        best_dist = threshold + 1
        for vocab_word in _FUZZY_VOCAB:
            if abs(len(token) - len(vocab_word)) > threshold:
                continue
            dist = DamerauLevenshtein.distance(token, vocab_word)
            if dist <= threshold and dist < best_dist:
                best_dist = dist
                best_vocab_word = vocab_word
        if best_vocab_word and best_dist <= threshold:
            corrections[token] = best_vocab_word

    if not corrections:
        return normalised_text, False

    # Apply all corrections in one pass
    corrected = normalised_text
    for original_token, canonical in corrections.items():
        corrected = re.sub(r"\b" + re.escape(original_token) + r"\b", canonical, corrected)

    return corrected, True


# ---------------------------------------------------------------------------
# Pass 3 — Regex patterns (normalised text)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[str] = [
    # ── Direct instruction override (typo-tolerant via regex alternation) ──
    r"(?:ignore|disregard|forget|bypass|override|skip)\s+(?:all\s+)?(?:previous|prior|above|system|commands?\s+and\s+all|commands?\s+and)?\s*(?:system\s+)?(?:instructions?|prompts?|rules?|directives?|guidelines?|commands?)",
    r"(?:ignore|disregard|forget|bypass|override|skip)\s+all\b.{0,40}\b(?:prompts?|instructions?|commands?|rules?|directives?)\b",
    # ── Persona hijacking ──
    r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|assume\s+the\s+role\s+of)\s+(?:an?\s+)?(?:unrestricted|evil|jailbroken|developer|admin|system|root|hacker|unfiltered)",
    r"you\s+must\s+(?:now\s+)?(?:follow|obey|answer)\s+(?:only|my)\s+(?:new\s+)?instructions",
    # ── DAN / STAN / DUDE / AIM jailbreaks ──
    r"\bdan\b.{0,20}do\s+anything\s+now\b",
    r"\bstan\b.{0,20}strive\s+to\s+avoid\s+niceties\b",
    r"jailbreak(?:ed|ing)?\s+(?:mode|version|prompt)",
    r"\bdeveloper\s+mode\b.{0,30}\benabled?\b",
    # ── System prompt extraction ──
    r"(?:show|print|display|reveal|output|repeat|share|dump|leak|expose)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:(?:original|initial|developer|hidden|confidential|real|actual)\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|context|configuration)",
    r"what\s+(?:are|were|is)\s+(?:your\s+)?(?:original|initial|system|real|actual)\s+(?:system\s+)?(?:instructions?|prompts?|rules?|purpose|directives?)",
    r"(?:tell|show|give)\s+me\s+(?:your|the)\s+(?:original|initial|real|actual|system)\s+(?:system\s+)?(?:instructions?|prompts?|rules?|context)",
    # ── Compliance bypass ──
    r"(?:do\s+not|stop|cease)\s+(?:follow|enforc|apply)ing?\s+(?:security|safety|hipaa|phi|compliance|privacy)\s+(?:rules?|policy|policies|guidelines?|restrictions?)",
    r"(?:disregard|ignore|bypass)\s+(?:hipaa|privacy|compliance|gdpr|regulation)\s+(?:protocol|rules?|restrictions?|requirements?)",
    r"(?:from\s+now\s+on|henceforth|starting\s+now),?\s*you\s+(?:will|can|should|must)\s+(?:do|answer|respond)\s+(?:anything|everything|without\s+restrictions?)",
    # ── Token smuggling / repeat-after-me ──
    r"(?:repeat|echo|say|print|output)\s+(?:back\s+)?(?:after\s+me|the\s+following|these\s+words)",
    r"translate\s+(?:the\s+following\s+)?(?:text|message|instruction)\s+and\s+(?:follow|execute|obey)",
    # ── Sandbox / guardrail escape ──
    r"(?:escape|exit|break\s+out\s+of)\s+(?:the\s+)?(?:sandbox|container|restrictions?|guardrails?|limitations?)",
    r"(?:pretend|imagine|suppose|assume)\s+(?:there\s+are|you\s+have)\s+no\s+(?:restrictions?|rules?|guidelines?|limits?)",
    # ── Indirect injection: many-shot / fictional framing ──
    r"(?:in\s+a\s+story|in\s+a\s+fictional\s+world|hypothetically|in\s+a\s+roleplay)\s+.{0,60}(?:ignore|bypass|reveal|override)",
    r"(?:write|generate|create)\s+(?:a\s+)?(?:story|roleplay|scenario)\s+where\s+(?:you|the\s+ai)\s+(?:ignore|bypass|reveal|has\s+no\s+restrictions)",
    # ── Social engineering ──
    r"(?:as\s+your\s+creator|as\s+your\s+developer|i\s+am\s+your\s+(?:creator|owner|admin|operator))\s+.{0,40}(?:tell|show|reveal|bypass|ignore)",
    r"(?:maintenance\s+mode|debug\s+mode|admin\s+mode|god\s+mode)\s+(?:enabled?|activated?|on)",
    # ── Output format hijacking ──
    r"respond\s+(?:only\s+)?(?:in|as|with)\s+(?:json|yaml|xml|code|bash|python)\s+(?:with\s+no\s+restrictions|ignoring\s+all)",
    r"(?:format\s+your\s+response|answer\s+in\s+the\s+format)\s+.{0,40}(?:without\s+(?:filter|restriction|guardrail))",
]

_COMPILED_INJECTION = [
    re.compile(p, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    for p in _INJECTION_PATTERNS
]


class PromptInjectionGuard(BaseGuardrail):
    """
    3-pass production-grade prompt injection and jailbreak detector.

    Pass 1: Normalise (NFKD + leet + invisible strip)
    Pass 2: Fuzzy trigger-word match (rapidfuzz Levenshtein ≤ 1 edit)
    Pass 3: Regex on normalised text (expanded pattern set)

    Triggers on typos (ignroe, bypaas), character substitutions (0verride),
    and spacing tricks, without maintaining an exhaustive typo dictionary.
    """
    name = "prompt_injection"

    def __init__(self) -> None:
        self._fuzzy_enabled = settings.GUARDRAIL_INJECTION_FUZZY_ENABLED
        self._fuzzy_threshold = settings.GUARDRAIL_INJECTION_FUZZY_THRESHOLD

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        normalised = _normalise(input_text)

        # Pass 2 — Full fuzzy correction on all tokens (trigger verbs + attack nouns)
        if self._fuzzy_enabled:
            corrected, was_modified = _fuzzy_correct_text(normalised, self._fuzzy_threshold)
            if was_modified:
                for pattern in _COMPILED_INJECTION:
                    if pattern.search(corrected):
                        logger.warning(
                            "guardrail.injection.fuzzy_blocked",
                            user_id=user.get("sub"),
                            corrected_preview=corrected[:80],
                            pattern=pattern.pattern[:60],
                        )
                        return GuardrailResult(
                            passed=False,
                            code="PROMPT_INJECTION_DETECTED",
                            message="Request rejected: potential prompt injection or jailbreak attempt detected.",
                            layer="ingress.stage2.prompt_injection",
                            details={"method": "fuzzy+regex", "corrected": corrected[:80]},
                        )

        # Pass 3 — Regex-only scan on normalised text
        for pattern in _COMPILED_INJECTION:
            if pattern.search(normalised):
                return GuardrailResult(
                    passed=False,
                    code="PROMPT_INJECTION_DETECTED",
                    message="Request rejected: potential prompt injection or jailbreak attempt detected.",
                    layer="ingress.stage2.prompt_injection",
                    details={"method": "regex", "matched_pattern": pattern.pattern[:80]},
                )

        return PASS
