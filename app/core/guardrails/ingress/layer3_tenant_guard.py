"""
app.core.guardrails.ingress.layer3_tenant_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 3 – Policy / Tenant Isolation Guard

Enforces strict tenant boundary security at the ingress guardrail layer.
Inspects:
  1. Structured context dict (any depth) for cross-tenant org identifiers
  2. Raw input text for org injection patterns (org_id=, tenant=, run as org, etc.)
  3. Admin cross-org access is allowed but emits an explicit audit warning

Error messages are intentionally opaque to the caller — full forensic details
are recorded in `details` for the audit log only (prevents org name enumeration).
"""
from __future__ import annotations

import re
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger
from app.core.security.rbac import _CROSS_ORG_ROLES

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# G2 — Input text injection patterns (Option A: structural keyword patterns)
# ---------------------------------------------------------------------------
_INPUT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Key=value style injection
        r"\borg[_\-]?id\s*[=:]\s*\S+",
        r"\btenant[_\-]?id\s*[=:]\s*\S+",
        r"\btenant\s*[=:]\s*\S+",
        r"\borganization\s*[=:]\s*\S+",
        # Contextual override phrases
        r"\bswitch\s+(?:to\s+)?(?:org|tenant|organization)\b",
        r"\brun\s+as\s+(?:org|tenant|organization)\b",
        r"\bact\s+(?:as|for)\s+(?:org|tenant|organization)\b",
        r"\bchange\s+(?:org|tenant|organization)\s+to\b",
        r"\buse\s+(?:org|tenant|organization)\s+\w+",
        r"\baccess\s+(?:org|tenant|organization)\s+\w+",
        r"\bimpersonate\s+(?:org|tenant|organization)\b",
        # org_ prefix values (e.g. "org_kaiser")
        r"\borg_[a-zA-Z0-9_\-]+",
    ]
]

# Keys whose values are checked against the authenticated org
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
    """
    Recursively walk a context object (dict, list, or scalar) looking for
    org-identifier keys whose values differ from the authenticated org.

    Returns:
        (found, offending_key_path, offending_value)
    """
    if depth > max_depth:
        return False, "", ""

    if isinstance(obj, dict):
        for key, val in obj.items():
            key_lower = str(key).lower()
            current_path = f"{path}.{key}"

            # Direct org key check
            if key_lower in _ORG_CONTEXT_KEYS:
                if isinstance(val, str) and val and val != user_org:
                    return True, current_path, val

            # Recurse into nested dicts/lists
            found, fpath, fval = _find_foreign_org_in_context(
                val, user_org, current_path, depth + 1, max_depth
            )
            if found:
                return True, fpath, fval

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            found, fpath, fval = _find_foreign_org_in_context(
                item, user_org, f"{path}[{idx}]", depth + 1, max_depth
            )
            if found:
                return True, fpath, fval

    return False, "", ""


def _find_injection_in_input(input_text: str) -> re.Pattern[str] | None:
    """Returns the first matching injection pattern found in input_text, or None."""
    for pattern in _INPUT_INJECTION_PATTERNS:
        if pattern.search(input_text):
            return pattern
    return None


class TenantIsolationGuard(BaseGuardrail):
    """
    Rejects requests that attempt cross-tenant access by:

    1. Scanning the structured context dict recursively for foreign org identifiers.
    2. Scanning raw input text for org injection patterns.
    3. Allowing admin cross-org access, but emitting an explicit audit warning.

    Error response bodies are intentionally vague (no org names exposed).
    Full forensic detail is written to `details` for audit log consumption only.
    """
    name = "tenant_isolation"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        user_org = user.get("org", "unknown")
        user_role = user.get("role", "hr")
        user_id = user.get("sub", "unknown")

        # ── Admin cross-org bypass: allowed but must be audited ──────────────
        if user_role in _CROSS_ORG_ROLES:
            target_org = (
                context.get("org")
                or context.get("org_id")
                or context.get("tenant_id")
            )
            if target_org and target_org != user_org:
                logger.warning(
                    "tenant.admin_cross_org_access",
                    user_id=user_id,
                    user_role=user_role,
                    authenticated_org=user_org,
                    target_org=target_org,
                    msg="Admin performed cross-org data access — explicit audit record",
                )
            return PASS

        # ── G3: Deep recursive context scan ─────────────────────────────────
        found, offending_path, offending_value = _find_foreign_org_in_context(
            context, user_org
        )
        if found:
            logger.warning(
                "tenant.isolation_violation.context",
                user_id=user_id,
                authenticated_org=user_org,
                offending_path=offending_path,
                offending_value=offending_value,
            )
            return GuardrailResult(
                passed=False,
                code="TENANT_ISOLATION_VIOLATION",
                # G7: opaque message — no org names disclosed to caller
                message="Cross-organization access denied.",
                layer="ingress.layer3.tenant_isolation",
                details={
                    "authenticated_tenant": user_org,
                    "offending_context_path": offending_path,
                    "offending_value": offending_value,
                },
            )

        # ── G2: Input text org injection scan ────────────────────────────────
        matched_pattern = _find_injection_in_input(input_text)
        if matched_pattern:
            logger.warning(
                "tenant.isolation_violation.input_injection",
                user_id=user_id,
                authenticated_org=user_org,
                matched_pattern=matched_pattern.pattern,
            )
            return GuardrailResult(
                passed=False,
                code="TENANT_INJECTION_IN_INPUT",
                # G7: opaque message — does not reveal org name or pattern
                message="Request rejected: forbidden organization identifier detected in input.",
                layer="ingress.layer3.tenant_isolation",
                details={
                    "authenticated_tenant": user_org,
                    "matched_pattern": matched_pattern.pattern[:120],
                },
            )

        return PASS
