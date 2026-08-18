"""
stage5_policy.rbac_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~
RBAC token budget and PHI access entitlement guards.
"""
from __future__ import annotations

from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_ROLE_BUDGETS: dict[str, int] = {
    "clinician": 2_000,
    "hr": 4_000,
    "compliance_officer": 8_000,
    "admin": 16_000,
}
_DEFAULT_BUDGET = 2_000

_PHI_ALLOWED_ROLES: frozenset[str] = frozenset(["admin", "compliance_officer"])


class RBACTokenBudgetGuard(BaseGuardrail):
    """Enforces per-role maximum input character budget."""
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
                layer="ingress.stage5.rbac_token_budget",
                details={"role": role, "input_length": input_len, "budget": budget},
            )
        return PASS


class PHIAccessEntitlementGuard(BaseGuardrail):
    """Enforces that only privileged roles may request PHI-bearing responses."""
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
                layer="ingress.stage5.phi_access_entitlement",
                details={"role": role, "requires_phi": True, "allowed_roles": sorted(_PHI_ALLOWED_ROLES)},
            )
        return PASS
