"""
stage4_phi_pii.presidio_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Production-grade PHI/PII detection using Microsoft Presidio.

Uses the unified PresidioEngine singleton in `app.core.phi.presidio_engine`,
which supports custom healthcare recognizers (NPI, DEA, MRN, License)
and thread-safe lazy-initialization.

Mode (controlled by settings.GUARDRAIL_PRESIDIO_INGRESS_MODE):
  "warn"  — log PHI types found, pass through to the masking pipeline (default)
  "block" — hard-reject the request if PHI found (for roles with no PHI entitlement)
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger
from app.core.phi.presidio_engine import analyze_pii

logger = get_logger(__name__)


class PresidioPHIGuard(BaseGuardrail):
    """
    Stage 4 — Microsoft Presidio PHI/PII detection guard.

    Uses a multi-recognizer NLP engine to find PHI patterns in free text.
    In warn mode (default): logs findings and passes to the masking pipeline.
    In block mode: rejects requests containing any PHI above the confidence threshold.
    """
    name = "presidio_phi"

    def __init__(self) -> None:
        self.enabled = settings.GUARDRAIL_PRESIDIO_INGRESS_ENABLED
        self.mode = settings.GUARDRAIL_PRESIDIO_INGRESS_MODE

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if not self.enabled:
            return PASS

        findings = analyze_pii(input_text)
        if not findings:
            return PASS

        # Build structured finding summary
        phi_types = list({f.type for f in findings})
        finding_count = len(findings)

        logger.warning(
            "guardrail.presidio.phi_detected_in_input",
            user_id=user.get("sub"),
            phi_types=phi_types,
            count=finding_count,
            mode=self.mode,
        )

        if self.mode == "block":
            return GuardrailResult(
                passed=False,
                code="PHI_IN_INPUT_BLOCKED",
                message=(
                    f"Request blocked: PHI/PII detected in input "
                    f"({finding_count} finding(s): {', '.join(phi_types)})."
                ),
                layer="ingress.stage4.presidio_phi",
                details={"phi_types": phi_types, "count": finding_count},
            )

        # warn mode: pass through to masking pipeline
        return GuardrailResult(
            passed=True,
            code="PHI_IN_INPUT_WARNED",
            message=f"Raw PHI detected in input ({', '.join(phi_types)}); proceeding with masking pipeline.",
            layer="ingress.stage4.presidio_phi",
            details={"phi_types": phi_types, "count": finding_count},
        )
