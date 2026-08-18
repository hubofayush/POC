"""
stage5_policy.topic_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Domain topic scope guardrail — checks that input is related to healthcare/compliance.

Mode is controlled by settings.GUARDRAIL_TOPIC_MODE:
  "warn"  — log finding and pass (default)
  "block" — reject with 422
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

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

_MIN_DOMAIN_HITS = 1
_MIN_LEN_FOR_SCOPE = 100


class TopicScopeGuard(BaseGuardrail):
    """
    Checks that the input is related to healthcare / compliance domain.
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
                layer="ingress.stage5.topic_scope",
                details=details,
            )
        else:
            logger.warning("guardrail.topic_scope.warn", **details, user_id=user.get("sub"))
            return GuardrailResult(
                passed=True,
                code="OFF_TOPIC_WARNED",
                message=msg,
                layer="ingress.stage5.topic_scope",
                details=details,
            )
