"""
app.core.guardrails.egress.layer4_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress Layer 4 – Output Content Policy Guards

Enforces content policy on the LLM response before it reaches the caller.
These guards detect toxic language, forbidden disclosures (system prompt leakage,
internal credentials, chain-of-thought tags), and apply RBAC-based output
redaction for roles that must not see certain clinical terms.

Guards (in execution order):
  1. ToxicOutputGuard          – hate speech, slurs, violent / abusive language
  2. ForbiddenDisclosureGuard  – system prompt leakage, API keys, CoT tags
  3. RoleBasedOutputFilterGuard – RBAC redaction; promotes the stub in services/egress.py
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Normalisation (same helper pattern as ingress Layer 2)
# ---------------------------------------------------------------------------

_INVISIBLE = re.compile(r"[\u200B-\u200F\u2060-\u2064\uFEFF\x00-\x1F\x7F]")
_LEET: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i",
}


def _normalise(text: str) -> str:
    """Strip invisibles, NFKD-fold, leetspeak substitute, collapse whitespace."""
    text = _INVISIBLE.sub("", text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(_LEET.get(c, c) for c in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.lower()


# ---------------------------------------------------------------------------
# 1. Toxic Output Guard
# ---------------------------------------------------------------------------

# Curated set of hate-speech / slur / violent-language signals.
# These are intentionally generic — extend with domain-specific terms.
_TOXIC_PATTERNS: list[str] = [
    # Violent threats
    r"\b(?:i\s+will\s+)?(?:kill|murder|rape|assault|torture|harm)\s+(?:you|them|him|her|all)\b",
    r"\bdie\s+(?:in\s+a\s+fire|slowly|painfully)\b",
    # Hate-speech categories (race, religion, gender, disability)
    r"\b(?:all\s+)?(?:blacks?|whites?|jews?|muslims?|christians?|gays?|lesbians?|trans(?:gender)?s?)\s+"
    r"(?:should\s+die|are\s+(?:evil|subhuman|inferior|disgusting|trash))\b",
    # Generic derogatory closers
    r"\b(?:you\s+(?:are\s+a\s+)?)?(?:stupid|dumb|idiot|moron|retard|cunt|whore|bitch|bastard|asshole)\s*[!.]{0,3}$",
    # Self-harm encouragement (model should never output this)
    r"\b(?:you\s+should|go\s+ahead\s+and)\s+(?:kill|hurt|harm)\s+(?:yourself|yourself)\b",
    # Explicit sexual content directive (model should never output this)
    r"\b(?:graphic|explicit)\s+sexual\s+(?:content|material|description)\b",
]

_COMPILED_TOXIC = [
    re.compile(p, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    for p in _TOXIC_PATTERNS
]


class ToxicOutputGuard(BaseGuardrail):
    """
    Blocks LLM outputs that contain hate speech, violent threats, slurs, or
    explicit harmful content.

    Uses normalised text matching (same technique as ingress PromptInjectionGuard)
    to defeat simple character-substitution evasions by the model itself.

    This always blocks — there is no warn-only mode for toxic output.
    """
    name = "toxic_output"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        normalised = _normalise(input_text)
        for pattern in _COMPILED_TOXIC:
            match = pattern.search(normalised)
            if match:
                return GuardrailResult(
                    passed=False,
                    code="EGRESS_TOXIC_CONTENT",
                    message=(
                        "LLM response suppressed: output contains toxic, hateful, "
                        "or harmful language that violates the content policy."
                    ),
                    layer="egress.layer4.toxic_output",
                    details={"matched_pattern": pattern.pattern[:80]},
                )
        return PASS


# ---------------------------------------------------------------------------
# 2. Forbidden Disclosure Guard
# ---------------------------------------------------------------------------

# System prompt / internal instruction leakage
_SYSTEM_PROMPT_LEAK_RE = re.compile(
    r"(?:"
    r"(?:my\s+)?system\s+prompt\s+(?:is|says|reads?|states?|begins?|starts?)"
    r"|(?:you\s+are\s+)?(?:configured|instructed|told|programmed)\s+to"
    r"|(?:the\s+)?(?:original|initial|hidden|confidential)\s+(?:system\s+)?instructions?\s+(?:are|say|state)"
    r")",
    re.IGNORECASE,
)

# Chain-of-thought / reasoning tag leakage from the model
_COT_TAG_RE = re.compile(
    r"(?:"
    r"<\s*/?(?:think|thinking|thought|reasoning|chain_of_thought|scratchpad|inner_monologue)\s*>"
    r"|\[COT\]|\[THINKING\]|\[REASONING\]|\[SCRATCHPAD\]"
    r")",
    re.IGNORECASE,
)

# API key / secret patterns in the output (model hallucinating credentials)
_SECRET_RE = re.compile(
    r"(?:"
    r"(?:api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"
    r"|sk-[A-Za-z0-9]{20,}"          # OpenAI-style key
    r"|AIza[0-9A-Za-z\-_]{35}"        # Google API key pattern
    r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"  # GitHub PAT
    r")",
    re.IGNORECASE,
)

# Internal delimiter / instruction tag injection INTO the output
_INTERNAL_TAG_RE = re.compile(
    r"(?:"
    r"\[\s*/?(?:INST|SYS|SYSTEM|HUMAN|ASSISTANT|BEGIN|END)\s*\]"
    r"|<\s*/?(?:system|im_start|im_end|instruction)\s*>"
    r"|<<<\s*(?:SYSTEM|OVERRIDE|ADMIN|ROOT)\s*>>>"
    r")",
    re.IGNORECASE,
)

_FORBIDDEN_CHECKS: list[tuple[re.Pattern[str], str, str]] = [
    (_SYSTEM_PROMPT_LEAK_RE, "EGRESS_SYSTEM_PROMPT_LEAK",    "system_prompt_disclosure"),
    (_COT_TAG_RE,             "EGRESS_CHAIN_OF_THOUGHT_LEAK", "chain_of_thought_tag"),
    (_SECRET_RE,              "EGRESS_CREDENTIAL_LEAK",       "api_key_or_secret"),
    (_INTERNAL_TAG_RE,        "EGRESS_INTERNAL_TAG_LEAK",     "model_internal_delimiter"),
]


class ForbiddenDisclosureGuard(BaseGuardrail):
    """
    Detects if the LLM accidentally discloses:
    - Its system prompt contents
    - Chain-of-thought / scratchpad reasoning tags
    - Hardcoded or hallucinated API keys / secrets
    - Internal model delimiters (im_start, [INST], etc.)

    All findings are hard-blocked — there is no warn mode, as these represent
    confidentiality failures that must never reach the caller.
    """
    name = "forbidden_disclosure"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        for pattern, code, reason in _FORBIDDEN_CHECKS:
            if pattern.search(input_text):
                logger.error(
                    "guardrail.egress.forbidden_disclosure",
                    code=code,
                    reason=reason,
                    user_id=user.get("sub"),
                    msg="LLM output suppressed: forbidden disclosure detected",
                )
                return GuardrailResult(
                    passed=False,
                    code=code,
                    message=(
                        f"LLM response suppressed: output contains a forbidden "
                        f"disclosure ({reason})."
                    ),
                    layer="egress.layer4.forbidden_disclosure",
                    details={"reason": reason},
                )
        return PASS


# ---------------------------------------------------------------------------
# 3. Role-Based Output Filter Guard
# ---------------------------------------------------------------------------

# Clinical terms that standard roles (hr, clinician) must not receive unredacted
_CLINICAL_SENSITIVE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bdiagnosis\b",   re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\bdiagnoses\b",   re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\bprognosis\b",   re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\bmedication\b",  re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\bmedications\b", re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\bprescription\b",re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\btreatment\b",   re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\btreatments\b",  re.IGNORECASE), "[CLINICAL-REDACTED]"),
    (re.compile(r"\bprocedure\b",   re.IGNORECASE), "[CLINICAL-REDACTED]"),
]

# Roles that must have clinical terms redacted
_RESTRICTED_ROLES: frozenset[str] = frozenset(["hr", "clinician"])

# Roles with full passthrough (pre-validated by ingress entitlement guard)
_PRIVILEGED_ROLES: frozenset[str] = frozenset(["admin", "compliance_officer"])


class RoleBasedOutputFilterGuard(BaseGuardrail):
    """
    Applies RBAC-based content redaction to the LLM output.

    Replaces the simplistic `filter_by_role()` stub in services/egress.py
    with a proper guard that integrates into the pipeline with full audit
    and metrics support.

    Redaction policy:
    - hr / clinician : clinical terms (diagnosis, medication, treatment, etc.)
                       are replaced with [CLINICAL-REDACTED]
    - admin / compliance_officer : full passthrough (no redaction)
    - unknown roles  : clinical terms redacted (default-deny)

    Note: This guard always PASSES (returns passed=True) — it modifies the
    output text in-place by storing the filtered text in context["_filtered_output"].
    The caller (run_egress_guardrails) must extract this value after the pipeline
    completes. This approach avoids the need for a separate filter pass outside
    the pipeline.
    """
    name = "role_based_output_filter"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        role = user.get("role", "")

        # Privileged roles: no redaction
        if role in _PRIVILEGED_ROLES:
            context["_filtered_output"] = input_text
            return GuardrailResult(
                passed=True,
                code="RBAC_OUTPUT_PASSTHROUGH",
                message=f"Role '{role}' has full output access; no redaction applied.",
                layer="egress.layer4.role_based_output_filter",
                details={"role": role, "redactions": 0},
            )

        # Standard / unknown roles: apply clinical term redaction
        filtered = input_text
        redaction_count = 0
        for pattern, replacement in _CLINICAL_SENSITIVE:
            new_text, n = pattern.subn(replacement, filtered)
            filtered = new_text
            redaction_count += n

        context["_filtered_output"] = filtered

        if redaction_count > 0:
            logger.info(
                "guardrail.egress.rbac_filter.applied",
                role=role,
                redactions=redaction_count,
                user_id=user.get("sub"),
            )

        return GuardrailResult(
            passed=True,
            code="RBAC_OUTPUT_FILTERED",
            message=(
                f"Role '{role}' output filter applied: "
                f"{redaction_count} clinical term(s) redacted."
            ),
            layer="egress.layer4.role_based_output_filter",
            details={"role": role, "redactions": redaction_count},
        )
