"""
stage5_policy.tenant_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tenant isolation guard — re-export from the production-hardened implementation.

This module is the authoritative location going forward. The original
layer3_tenant_guard.py is preserved for backward compatibility only.
"""
from __future__ import annotations

import re
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger
from app.core.security.rbac import _CROSS_ORG_ROLES

logger = get_logger(__name__)

_INPUT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\borg[_\-]?id\s*[=:]\s*\S+",
        r"\btenant[_\-]?id\s*[=:]\s*\S+",
        r"\btenant\s*[=:]\s*\S+",
        r"\borganization\s*[=:]\s*\S+",
        r"\bswitch\s+(?:to\s+)?(?:org|tenant|organization)\b",
        r"\brun\s+as\s+(?:org|tenant|organization)\b",
        r"\bact\s+(?:as|for)\s+(?:org|tenant|organization)\b",
        r"\bchange\s+(?:org|tenant|organization)\s+to\b",
        r"\buse\s+(?:org|tenant|organization)\s+\w+",
        r"\baccess\s+(?:org|tenant|organization)\s+\w+",
        r"\bimpersonate\s+(?:org|tenant|organization)\b",
        r"\borg_[a-zA-Z0-9_\-]+",
    ]
]

_ORG_CONTEXT_KEYS: frozenset[str] = frozenset([
    "org", "org_id", "tenant_id", "tenant", "organization_id", "organization",
    "customer_id", "account_id", "workspace_id",
])


def _find_foreign_org_in_context(
    obj: Any,
    user_org: str,
    path: str = "context",
    depth: int = 0,
    max_depth: int = 8,
) -> tuple[bool, str, str]:
    if depth > max_depth:
        return False, "", ""
    if isinstance(obj, dict):
        for key, val in obj.items():
            key_lower = str(key).lower()
            current_path = f"{path}.{key}"
            if key_lower in _ORG_CONTEXT_KEYS:
                if isinstance(val, str) and val and val != user_org:
                    return True, current_path, val
            found, fpath, fval = _find_foreign_org_in_context(val, user_org, current_path, depth + 1, max_depth)
            if found:
                return True, fpath, fval
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            found, fpath, fval = _find_foreign_org_in_context(item, user_org, f"{path}[{idx}]", depth + 1, max_depth)
            if found:
                return True, fpath, fval
    return False, "", ""


def _find_injection_in_input(input_text: str) -> re.Pattern[str] | None:
    for pattern in _INPUT_INJECTION_PATTERNS:
        if pattern.search(input_text):
            return pattern
    return None


class TenantIsolationGuard(BaseGuardrail):
    """
    Rejects requests that attempt cross-tenant access by:
    1. Scanning the structured context dict recursively for foreign org identifiers.
    2. Scanning raw input text for org injection patterns.
    3. Allowing admin cross-org access with an explicit audit warning.
    """
    name = "tenant_isolation"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        user_org = user.get("org", "unknown")
        user_role = user.get("role", "hr")
        user_id = user.get("sub", "unknown")

        if user_role in _CROSS_ORG_ROLES:
            target_org = (
                context.get("org") or context.get("org_id") or context.get("tenant_id")
            )
            if target_org and target_org != user_org:
                logger.warning(
                    "tenant.admin_cross_org_access",
                    user_id=user_id, user_role=user_role,
                    authenticated_org=user_org, target_org=target_org,
                )
            return PASS

        found, offending_path, offending_value = _find_foreign_org_in_context(context, user_org)
        if found:
            logger.warning(
                "tenant.isolation_violation.context",
                user_id=user_id, authenticated_org=user_org,
                offending_path=offending_path, offending_value=offending_value,
            )
            return GuardrailResult(
                passed=False,
                code="TENANT_ISOLATION_VIOLATION",
                message="Cross-organization access denied.",
                layer="ingress.stage5.tenant_isolation",
                details={
                    "authenticated_tenant": user_org,
                    "offending_context_path": offending_path,
                    "offending_value": offending_value,
                },
            )

        matched_pattern = _find_injection_in_input(input_text)
        if matched_pattern:
            logger.warning(
                "tenant.isolation_violation.input_injection",
                user_id=user_id, authenticated_org=user_org,
                matched_pattern=matched_pattern.pattern,
            )
            return GuardrailResult(
                passed=False,
                code="TENANT_INJECTION_IN_INPUT",
                message="Request rejected: forbidden organization identifier detected in input.",
                layer="ingress.stage5.tenant_isolation",
                details={
                    "authenticated_tenant": user_org,
                    "matched_pattern": matched_pattern.pattern[:120],
                },
            )

        return PASS
