"""
app.core.guardrails.base
~~~~~~~~~~~~~~~~~~~~~~~~
Abstract base types shared across all guardrail layers.

GuardrailResult  – immutable result of a single guard evaluation.
GuardrailException – FastAPI-compatible exception raised when a guard blocks.
BaseGuardrail    – ABC every guard must implement.
GuardrailPipeline – runs guards in order and short-circuits on first failure.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GuardrailResult:
    """Immutable result object returned by every guard."""
    passed: bool
    code: str = ""
    message: str = ""
    layer: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "code": self.code,
            "message": self.message,
            "layer": self.layer,
            "details": self.details,
        }


PASS = GuardrailResult(passed=True, code="OK", message="Guard passed")


class GuardrailException(Exception):
    """
    Raised by the pipeline when a guard blocks a request.

    Carries the full GuardrailResult so the error handler can
    build an RFC 9457 + extensions response body.
    """
    def __init__(self, result: GuardrailResult, trace_id: str = "") -> None:
        self.result = result
        self.trace_id = trace_id
        super().__init__(result.message)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseGuardrail(ABC):
    """Every concrete guard must implement `check`."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable guard identifier (used in audit logs)."""

    @abstractmethod
    async def check(
        self,
        input_text: str,
        context: dict[str, Any],
        user: dict[str, Any],
    ) -> GuardrailResult:
        """
        Evaluate the guard.

        Returns GuardrailResult with ``passed=True`` if the request is safe,
        or ``passed=False`` (with code + message) if it must be blocked.
        """


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

class GuardrailPipeline:
    """
    Runs a sequence of guards in declaration order.
    Short-circuits and raises GuardrailException on the first failure.
    """

    def __init__(self, guards: list[BaseGuardrail]) -> None:
        self._guards = guards

    async def run(
        self,
        input_text: str,
        context: dict[str, Any],
        user: dict[str, Any],
        trace_id: str = "",
    ) -> list[GuardrailResult]:
        """
        Execute every guard sequentially.

        Returns a list of all passed GuardrailResults.
        Raises GuardrailException immediately on first failure.
        """
        results: list[GuardrailResult] = []
        t_start = time.monotonic()

        for guard in self._guards:
            result = await guard.check(input_text, context, user)
            results.append(result)
            if not result.passed:
                raise GuardrailException(result=result, trace_id=trace_id)

        elapsed_ms = round((time.monotonic() - t_start) * 1000, 2)
        results.append(
            GuardrailResult(
                passed=True,
                code="PIPELINE_PASSED",
                message=f"All {len(self._guards)} guards passed in {elapsed_ms}ms",
                layer="pipeline",
            )
        )
        return results
