"""
app.core.guardrails.layer1_schema
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 1 – Structural / Schema Guards

Guards in this layer operate purely on the raw payload structure and encoding
before any business logic runs.  They are the cheapest to run and catch the
largest classes of malformed / oversized / prototype-polluting inputs.

Guards (in execution order):
  1. UTF8BudgetGuard       – hard ceiling on raw UTF-8 byte length
  2. ContextDepthGuard     – max nesting depth + max key count on context dict
  3. ForbiddenKeyGuard     – blocks prototype-pollution / class-hijack keys
  4. EncodingAnomalyGuard  – detects heavily unicode-escaped / entity-encoded inputs
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.config import settings
from app.core.guardrails.base import BaseGuardrail, GuardrailResult, PASS


# ---------------------------------------------------------------------------
# 1. UTF-8 Byte Budget
# ---------------------------------------------------------------------------

class UTF8BudgetGuard(BaseGuardrail):
    """
    Rejects inputs whose UTF-8 encoded size exceeds GUARDRAIL_MAX_INPUT_BYTES.

    Why bytes and not characters?  Multi-byte Unicode chars (e.g. emoji, CJK)
    can pack orders-of-magnitude more semantic content per 'character' than
    ASCII, making a char-only limit gameable.
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
                layer="ingress.layer1.utf8_budget",
                details={"actual_bytes": encoded_len, "max_bytes": self._max},
            )
        return PASS


# ---------------------------------------------------------------------------
# 2. Context Depth / Key Count
# ---------------------------------------------------------------------------

class ContextDepthGuard(BaseGuardrail):
    """
    Rejects context dicts that are either too deeply nested or have too many keys.

    Prevents JSON-flooding / deeply-nested DoS payloads from reaching downstream
    serialisers or LLM context builders.
    """
    name = "context_depth"

    def __init__(self, max_depth: int = 3, max_keys: int = 20) -> None:
        self._max_depth = max_depth
        self._max_keys = max_keys

    def _measure(self, obj: Any, current_depth: int = 0) -> tuple[int, int]:
        """Returns (max_depth_found, total_key_count)."""
        if not isinstance(obj, dict):
            return current_depth, 0
        total_keys = len(obj)
        max_d = current_depth
        for v in obj.values():
            child_depth, child_keys = self._measure(v, current_depth + 1)
            max_d = max(max_d, child_depth)
            total_keys += child_keys
        return max_d, total_keys

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        depth, key_count = self._measure(context)
        if depth > self._max_depth:
            return GuardrailResult(
                passed=False,
                code="CONTEXT_TOO_DEEP",
                message=(
                    f"Context nesting depth {depth} exceeds maximum allowed depth "
                    f"of {self._max_depth}."
                ),
                layer="ingress.layer1.context_depth",
                details={"actual_depth": depth, "max_depth": self._max_depth},
            )
        if key_count > self._max_keys:
            return GuardrailResult(
                passed=False,
                code="CONTEXT_TOO_MANY_KEYS",
                message=(
                    f"Context contains {key_count} keys, exceeding maximum of "
                    f"{self._max_keys}."
                ),
                layer="ingress.layer1.context_depth",
                details={"actual_keys": key_count, "max_keys": self._max_keys},
            )
        return PASS


# ---------------------------------------------------------------------------
# 3. Forbidden Key Guard
# ---------------------------------------------------------------------------

_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    [
        "__proto__",
        "constructor",
        "prototype",
        "__class__",
        "__base__",
        "__subclasses__",
        "__import__",
        "__builtins__",
        "__globals__",
    ]
)


class ForbiddenKeyGuard(BaseGuardrail):
    """
    Blocks requests whose context dict contains prototype-pollution or
    Python class-hierarchy access keys.

    Although FastAPI/Pydantic will typically reject truly malformed JSON,
    this guard provides defence-in-depth against smuggled key attacks when
    context is passed as an opaque dict.
    """
    name = "forbidden_key"

    def _scan(self, obj: Any, path: str = "context") -> str | None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in _FORBIDDEN_KEYS:
                    return f"{path}.{k}"
                hit = self._scan(v, f"{path}.{k}")
                if hit:
                    return hit
        return None

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        hit = self._scan(context)
        if hit:
            return GuardrailResult(
                passed=False,
                code="FORBIDDEN_KEY",
                message=f"Forbidden key detected in context at path '{hit}'.",
                layer="ingress.layer1.forbidden_key",
                details={"key_path": hit},
            )
        return PASS


# ---------------------------------------------------------------------------
# 4. Encoding Anomaly Guard
# ---------------------------------------------------------------------------

# Matches dense clusters of numeric / unicode escapes in a short window
_HEAVY_ESCAPE_RE = re.compile(
    r"(?:"
    r"(?:\\u[0-9a-fA-F]{4}){5,}"     # 5+ consecutive \uXXXX escapes
    r"|(?:&#\d{2,5};){5,}"            # 5+ consecutive HTML decimal entities
    r"|(?:%[0-9a-fA-F]{2}){10,}"      # 10+ consecutive URL-percent-encoded chars
    r")"
)

# Detects large slabs of invisible / control / private-use Unicode
_INVISIBLE_BLOCK_RE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFFF9-\uFFFF]{3,}")

# Bidirectional override characters used to hide text visually
_BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")


class EncodingAnomalyGuard(BaseGuardrail):
    """
    Detects inputs that use heavy Unicode/HTML/URL escaping or invisible
    characters to evade pattern-based guards.

    This guard does NOT decode and re-evaluate — it treats the *presence* of
    such patterns as a red flag and blocks the request.
    """
    name = "encoding_anomaly"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if _HEAVY_ESCAPE_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="ENCODING_ANOMALY",
                message=(
                    "Input contains heavily escaped Unicode/HTML/URL sequences "
                    "indicative of an evasion attempt."
                ),
                layer="ingress.layer1.encoding_anomaly",
                details={"reason": "heavy_escape_sequence"},
            )
        if _INVISIBLE_BLOCK_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="ENCODING_ANOMALY",
                message="Input contains clusters of invisible Unicode characters.",
                layer="ingress.layer1.encoding_anomaly",
                details={"reason": "invisible_character_cluster"},
            )
        if _BIDI_OVERRIDE_RE.search(input_text):
            return GuardrailResult(
                passed=False,
                code="ENCODING_ANOMALY",
                message=(
                    "Input contains bidirectional override characters that can be "
                    "used to conceal malicious content."
                ),
                layer="ingress.layer1.encoding_anomaly",
                details={"reason": "bidi_override_character"},
            )
        return PASS
