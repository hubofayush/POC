"""
stage1_structural.schema_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Context schema validation: max nesting depth, key count, and forbidden prototype keys.
"""
from __future__ import annotations

from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_FORBIDDEN_KEYS: frozenset[str] = frozenset([
    "__proto__", "constructor", "prototype", "__class__",
    "__base__", "__subclasses__", "__import__", "__builtins__", "__globals__",
])


class ContextDepthGuard(BaseGuardrail):
    """Rejects context dicts that are too deeply nested or have too many total keys."""
    name = "context_depth"

    def __init__(self, max_depth: int = 3, max_keys: int = 20) -> None:
        self._max_depth = max_depth
        self._max_keys = max_keys

    def _measure(self, obj: Any, current_depth: int = 0) -> tuple[int, int]:
        if not isinstance(obj, dict):
            return current_depth, 0
        total_keys = len(obj)
        max_d = current_depth
        for v in obj.values():
            child_depth, child_keys = self._measure(v, current_depth + 1)
            max_d = max(max_d, child_depth)
            total_keys += child_keys
        return max_d, total_keys

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        depth, key_count = self._measure(context)
        if depth > self._max_depth:
            return GuardrailResult(
                passed=False,
                code="CONTEXT_TOO_DEEP",
                message=f"Context nesting depth {depth} exceeds maximum of {self._max_depth}.",
                layer="ingress.stage1.context_depth",
                details={"actual_depth": depth, "max_depth": self._max_depth},
            )
        if key_count > self._max_keys:
            return GuardrailResult(
                passed=False,
                code="CONTEXT_TOO_MANY_KEYS",
                message=f"Context contains {key_count} keys, exceeding maximum of {self._max_keys}.",
                layer="ingress.stage1.context_depth",
                details={"actual_keys": key_count, "max_keys": self._max_keys},
            )
        return PASS


class ForbiddenKeyGuard(BaseGuardrail):
    """Blocks prototype-pollution and Python class-hierarchy access keys in context."""
    name = "forbidden_key"

    def _scan(self, obj: Any, path: str = "context") -> str | None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in _FORBIDDEN_KEYS:
                    return f"{path}.{k}"
                hit = self._scan(v, f"{path}.{k}")
                if hit:
                    return hit
        return None

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        hit = self._scan(context)
        if hit:
            return GuardrailResult(
                passed=False,
                code="FORBIDDEN_KEY",
                message=f"Forbidden key detected in context at path '{hit}'.",
                layer="ingress.stage1.forbidden_key",
                details={"key_path": hit},
            )
        return PASS
