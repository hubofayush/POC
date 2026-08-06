"""
app.core.guardrails.layer3_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 3 – Consent & RBAC Policy Guards

Enforces business-level access control policies *before* any AI call is made.

Guards (in execution order):
  1. ConsentGuard              – request must carry consent_granted == True
  2. RBACTokenBudgetGuard      – per-role maximum input character budget
  3. PHIAccessEntitlementGuard – requires_phi=True requires elevated role
"""
from __future__ import annotations

from typing import Any

from app.core.guardrails.base import BaseGuardrail, GuardrailResult, PASS


# ---------------------------------------------------------------------------
# Per-role character budgets
# Adjust these if your D3 model has different context/billing constraints.
# ---------------------------------------------------------------------------
_ROLE_BUDGETS: dict[str, int] = {
    "clinician": 2_000,
    "hr": 4_000,
    "compliance_officer": 8_000,
    "admin": 16_000,
}
_DEFAULT_BUDGET = 2_000  # conservative default for unknown roles

# Roles that are permitted to request PHI access
_PHI_ALLOWED_ROLES: frozenset[str] = frozenset(["admin", "compliance_officer"])


# ---------------------------------------------------------------------------
# 1. Consent Guard
# ---------------------------------------------------------------------------

class ConsentGuard(BaseGuardrail):
    """
    Blocks requests where the caller has explicitly set consent_granted = False.

    The default (key absent) is treated as granted to avoid breaking
    existing integrations; explicit denial is always enforced.
    """
    name = "consent"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        consent = context.get("consent_granted", True)
        if consent is False:
            return GuardrailResult(
                passed=False,
                code="CONSENT_DENIED",
                message="Request blocked: patient consent has not been granted.",
                layer="ingress.layer3.consent",
                details={"consent_granted": False},
            )
        return PASS


# ---------------------------------------------------------------------------
# 2. RBAC Token Budget Guard
# ---------------------------------------------------------------------------

class RBACTokenBudgetGuard(BaseGuardrail):
    """
    Enforces a per-role maximum input length (character count).

    Prevents low-privilege roles from submitting large inputs that could
    trigger expensive LLM calls or context-window attacks.
    """
    name = "rbac_token_budget"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        role = user.get("role", "")
        budget = _ROLE_BUDGETS.get(role, _DEFAULT_BUDGET)
        input_len = len(input_text)

        if input_len > budget:
            return GuardrailResult(
                passed=False,
                code="TOKEN_BUDGET_EXCEEDED",
                message=(
                    f"Input length {input_len:,} chars exceeds the {budget:,}-char "
                    f"budget allowed for role '{role}'."
                ),
                layer="ingress.layer3.rbac_token_budget",
                details={
                    "role": role,
                    "input_length": input_len,
                    "budget": budget,
                },
            )
        return PASS


# ---------------------------------------------------------------------------
# 3. PHI Access Entitlement Guard
# ---------------------------------------------------------------------------

class PHIAccessEntitlementGuard(BaseGuardrail):
    """
    Enforces that only privileged roles may request PHI-bearing responses.

    If context.requires_phi == True but the caller's role is not in the
    PHI_ALLOWED_ROLES set, the request is rejected with HTTP 403.
    """
    name = "phi_access_entitlement"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        requires_phi = context.get("requires_phi", False)
        role = user.get("role", "")

        if requires_phi and role not in _PHI_ALLOWED_ROLES:
            return GuardrailResult(
                passed=False,
                code="PHI_ACCESS_DENIED",
                message=(
                    f"Role '{role}' is not authorised to request PHI-bearing responses. "
                    f"Requires one of: {sorted(_PHI_ALLOWED_ROLES)}."
                ),
                layer="ingress.layer3.phi_access_entitlement",
                details={
                    "role": role,
                    "requires_phi": True,
                    "allowed_roles": sorted(_PHI_ALLOWED_ROLES),
                },
            )
        return PASS
