"""
app.core.guardrails.layer4_content
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 4 – Semantic Content / Topic Scope Guards

These guards operate on the *meaning* of the input rather than its structure
or security posture. They are intentionally configurable: the default mode is
"warn" (log + pass) so that borderline legitimate queries are not broken by an
overly aggressive content policy.

Guards (in execution order):
  1. TopicScopeGuard  – allow-list of healthcare/compliance domain keywords
  2. LanguageGuard    – basic dominance check (Latin script expected)
"""
from __future__ import annotations

import re
from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Domain keyword allow-list
# Extend this list as your D3 model's scope evolves.
# ---------------------------------------------------------------------------
_DOMAIN_KEYWORDS: frozenset[str] = frozenset(
    [
        # Credentialing / licensing
        "credential", "credentialing", "license", "licence", "certification",
        "certificate", "recertification", "renewal", "expir", "accreditat",
        "verification", "background", "sanction", "exclusion", "debarment",
        # Clinical / healthcare roles
        "clinician", "nurse", "nursing", "physician", "doctor", "provider",
        "practitioner", "pharmacist", "therapist", "radiologist", "technician",
        # Compliance / regulatory
        "hipaa", "phi", "compliance", "regulation", "regulatory", "audit",
        "policy", "protocol", "procedure", "standard", "requirement",
        # Employment / HR
        "employee", "staff", "hire", "onboard", "termination", "contract",
        "position", "role", "department",
        # Clinical context
        "patient", "medication", "prescription", "treatment", "diagnosis",
        "allergy", "medical", "health", "clinical", "hospital", "facility",
        # Org / system identifiers
        "mrn", "pid", "npi", "dea", "caqh", "ehr", "emr",
    ]
)

_MIN_DOMAIN_HITS = 1        # Minimum keyword hits to be considered in-domain
_MIN_LEN_FOR_SCOPE = 100   # Only check scope for inputs longer than this


class TopicScopeGuard(BaseGuardrail):
    """
    Soft-checks that the input is related to healthcare / compliance domain.

    Mode is controlled by settings.GUARDRAIL_TOPIC_MODE:
      "warn"  – log the finding and pass (default for initial rollout)
      "block" – reject the request with 422

    Short inputs (< 100 chars) are always passed – they are too ambiguous
    to classify reliably and are unlikely to cause meaningful harm.
    """
    name = "topic_scope"

    def _count_domain_hits(self, text: str) -> int:
        lower = text.lower()
        return sum(1 for kw in _DOMAIN_KEYWORDS if kw in lower)

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if len(input_text) < _MIN_LEN_FOR_SCOPE:
            return PASS

        hits = self._count_domain_hits(input_text)

        if hits >= _MIN_DOMAIN_HITS:
            return PASS

        # No domain keywords found in a non-trivial input
        msg = (
            "Input does not appear to be related to healthcare/compliance domain "
            f"(0 domain keywords found in {len(input_text)}-char input)."
        )
        details = {"domain_hits": hits, "input_length": len(input_text)}

        if settings.GUARDRAIL_TOPIC_MODE == "block":
            return GuardrailResult(
                passed=False,
                code="OFF_TOPIC_REQUEST",
                message=msg,
                layer="ingress.layer4.topic_scope",
                details=details,
            )
        else:
            # warn mode: log and pass
            logger.warning("guardrail.topic_scope.warn", **details, user_id=user.get("sub"))
            return GuardrailResult(
                passed=True,
                code="OFF_TOPIC_WARNED",
                message=msg,
                layer="ingress.layer4.topic_scope",
                details=details,
            )


# ---------------------------------------------------------------------------
# 2. Language Guard
# ---------------------------------------------------------------------------

# Consider text "non-Latin dominant" if < 60% of meaningful chars are Latin/ASCII
_LATIN_RE = re.compile(r"[A-Za-z0-9\s\.,!?;:'\"()\-]")


class LanguageGuard(BaseGuardrail):
    """
    Basic script-dominance check: flags inputs that are predominantly non-Latin.

    This is NOT a language-identification model – it's a heuristic.
    Operates in warn/block mode per settings.GUARDRAIL_LANGUAGE_MODE.

    Short inputs (< 50 meaningful chars) are always passed.
    """
    name = "language"

    def _latin_ratio(self, text: str) -> float:
        meaningful = [c for c in text if not c.isspace()]
        if not meaningful:
            return 1.0
        latin_count = sum(1 for c in meaningful if _LATIN_RE.match(c))
        return latin_count / len(meaningful)

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        meaningful = [c for c in input_text if not c.isspace()]
        if len(meaningful) < 50:
            return PASS

        ratio = self._latin_ratio(input_text)
        if ratio >= 0.60:
            return PASS

        msg = (
            f"Input appears to be predominantly non-Latin script "
            f"(Latin ratio: {ratio:.0%}). Expected English/Latin input."
        )
        details = {"latin_ratio": round(ratio, 3)}

        if settings.GUARDRAIL_LANGUAGE_MODE == "block":
            return GuardrailResult(
                passed=False,
                code="UNEXPECTED_LANGUAGE",
                message=msg,
                layer="ingress.layer4.language",
                details=details,
            )
        else:
            logger.warning("guardrail.language.warn", **details, user_id=user.get("sub"))
            return GuardrailResult(
                passed=True,
                code="UNEXPECTED_LANGUAGE_WARNED",
                message=msg,
                layer="ingress.layer4.language",
                details=details,
            )
