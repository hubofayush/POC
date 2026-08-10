"""
app.core.guardrails.egress.layer2_phi
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress Layer 2 – PHI / PII Leak Prevention Guard

Runs the full hybrid PHI detection stack (Presidio NLP + regex) on the raw
LLM output BEFORE mask_phi() is applied downstream.

Purpose
-------
This guard is a *forensic audit checkpoint*, not a replacement for masking.
It answers the question:
    "Did the model return raw PHI in its response?"

If yes, the finding is immediately logged so the SIEM / audit trail captures
a record of the PHI-bearing generation event, regardless of whether masking
succeeded downstream.

Mode
----
Controlled by settings.GUARDRAIL_EGRESS_PHI_MODE:
  "warn"  – log the finding, return passed=True (masker will clean it up).
             This is the safe-rollout default.
  "block" – suppress the entire response; raise EgressGuardrailException.

Guards:
  1. PHILeakGuard – Presidio NLP + regex detection on LLM output
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger
from app.core.phi.detector import detect_phi

logger = get_logger(__name__)


class PHILeakGuard(BaseGuardrail):
    """
    Detects raw PHI/PII in the LLM's output text.

    This fires BEFORE the mask_phi() pipeline runs, giving the audit trail
    a raw forensic record. In "warn" mode it always passes so the downstream
    masker can sanitise the output. In "block" mode it suppresses the response
    entirely — use this when zero PHI tolerance is required.

    Role bypass: admin and compliance_officer are allowed PHI in output
    (they have the entitlement from PHIAccessEntitlementGuard on ingress).
    """
    name = "phi_leak"

    # Roles whose PHI access was pre-approved by ingress L3
    _BYPASS_ROLES: frozenset[str] = frozenset(["admin", "compliance_officer"])

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        role = user.get("role", "")

        # Privileged roles: PHI bypass already validated on ingress — no check needed
        if role in self._BYPASS_ROLES:
            return PASS

        findings = detect_phi(input_text)
        if not findings:
            return PASS

        phi_types = sorted({f.type for f in findings})
        phi_count = len(findings)
        user_id = user.get("sub", "unknown")

        log_payload = {
            "phi_types": phi_types,
            "phi_count": phi_count,
            "user_id": user_id,
            "user_role": role,
            "mode": settings.GUARDRAIL_EGRESS_PHI_MODE,
        }

        if settings.GUARDRAIL_EGRESS_PHI_MODE == "block":
            logger.error(
                "guardrail.egress.phi_leak.blocked",
                **log_payload,
                msg="LLM output contained raw PHI; response suppressed",
            )
            return GuardrailResult(
                passed=False,
                code="EGRESS_PHI_LEAK",
                message=(
                    f"LLM response suppressed: raw PHI detected in output "
                    f"({phi_count} finding(s): {', '.join(phi_types)}). "
                    "Response has been blocked to prevent data exposure."
                ),
                layer="egress.layer2.phi_leak",
                details={
                    "phi_types": phi_types,
                    "phi_count": phi_count,
                    "role": role,
                },
            )

        # warn mode: log the alarm, pass through to masking pipeline
        logger.warning(
            "guardrail.egress.phi_leak.warned",
            **log_payload,
            msg="PHI detected in LLM output; forwarding to mask_phi() pipeline",
        )
        return GuardrailResult(
            passed=True,
            code="EGRESS_PHI_LEAK_WARNED",
            message=(
                f"Raw PHI detected in LLM output ({phi_count} finding(s): "
                f"{', '.join(phi_types)}). Forwarding to masking pipeline."
            ),
            layer="egress.layer2.phi_leak",
            details={
                "phi_types": phi_types,
                "phi_count": phi_count,
                "role": role,
            },
        )
