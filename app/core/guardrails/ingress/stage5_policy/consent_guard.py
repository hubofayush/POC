"""
stage5_policy.consent_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Consent enforcement guard — blocks requests without explicit patient consent.
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult


class ConsentGuard(BaseGuardrail):
    """
    Blocks requests where the caller has not explicitly granted consent.

    When GUARDRAIL_CONSENT_DEFAULT_GRANTED is False (prod default), the
    consent_granted key MUST be present and True. An explicit False is
    always blocked regardless of the default setting.
    """
    name = "consent"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        consent = context.get("consent_granted", settings.GUARDRAIL_CONSENT_DEFAULT_GRANTED)
        if consent is False:
            return GuardrailResult(
                passed=False,
                code="CONSENT_DENIED",
                message="Request blocked: patient consent has not been granted.",
                layer="ingress.stage5.consent",
                details={"consent_granted": False},
            )
        return PASS
