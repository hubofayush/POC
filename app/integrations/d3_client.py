"""
app.integrations.d3_client
~~~~~~~~~~~~~~~~~~~~~~~~~~
Hardened D3 downstream client: per-attempt timeout, retry with exponential
backoff on retryable failures, and a circuit breaker so a failing D3 backend
cannot cascade into the gateway.

The default provider is the in-memory mock (POC). A real HTTP provider can be
injected; it should raise D3ProviderError(retryable=True) for connect errors,
5xx or 429-class responses, and D3ProviderError(retryable=False) otherwise.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

Provider = Callable[[str, str, dict], Awaitable[dict]]


class D3CallError(Exception):
    """Downstream call failed after exhausting retries."""


class CircuitOpenError(D3CallError):
    """Circuit breaker is open — downstream is presumed unavailable."""


class D3ProviderError(Exception):
    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


class CircuitBreaker:
    """Simple closed / open / half-open circuit breaker (single process)."""

    def __init__(self, failure_threshold: int, reset_seconds: float):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.state = "closed"  # closed | open | half_open
        self.failures = 0
        self.opened_at: float | None = None

    def allow_request(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "half_open":
            return True  # single probe in flight
        # open: allow a probe after the reset window
        if time.monotonic() - (self.opened_at or 0) >= self.reset_seconds:
            self.state = "half_open"
            return True
        return False

    def record_success(self):
        if self.state == "half_open":
            logger.info(
                "egress.d3.circuit_closed",
                msg="D3 circuit breaker closed after successful probe",
            )
        self.state = "closed"
        self.failures = 0
        self.opened_at = None

    def record_failure(self):
        if self.state == "half_open":
            self.state = "open"
            self.opened_at = time.monotonic()
            logger.warning(
                "egress.d3.circuit_reopened",
                msg="D3 probe failed; circuit breaker reopened",
            )
            return
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "open"
            self.opened_at = time.monotonic()
            logger.warning(
                "egress.d3.circuit_opened",
                failures=self.failures,
                msg="D3 circuit breaker opened",
            )


class D3Client:
    def __init__(self, provider: Provider | None = None):
        self.provider: Provider = provider or self._mock_provider
        self.breaker = CircuitBreaker(
            failure_threshold=settings.D3_CIRCUIT_FAILURE_THRESHOLD,
            reset_seconds=settings.D3_CIRCUIT_RESET_SEC,
        )

    async def _mock_provider(self, trace_id: str, input: str, context: dict) -> dict:
        text = input.lower()
        if "expired" in text or "expiry" in text:
            return {
                "output": "License RN-987654 expired on March 12, 2026. Renewal due within 30 days.",
                "citations": ["MOCK-GOV-RN987654", "MOCK-POLICY-RENEWAL"],
                "tier": "cheap",
            }
        if "missing" in text:
            return {
                "output": "Missing: BLS Certification, HIPAA Training (expired). Action required.",
                "citations": ["MOCK-POLICY-SURGEON-REQS"],
                "tier": "frontier",
            }
        return {
            "output": "All credentials verified. Compliance status: ACTIVE.",
            "citations": ["MOCK-COMPLIANCE-SUMMARY"],
            "tier": "cheap",
        }

    async def call_invoke(self, trace_id: str, input: str, context: dict) -> dict:
        if not self.breaker.allow_request():
            raise CircuitOpenError(
                "Downstream D3 circuit breaker is open; request not attempted"
            )

        max_attempts = settings.D3_MAX_RETRIES + 1
        last_error: Exception | None = None
        retryable_failure = False

        for attempt in range(1, max_attempts + 1):
            try:
                result = await asyncio.wait_for(
                    self.provider(trace_id, input, context),
                    timeout=settings.D3_TIMEOUT_SEC,
                )
                self.breaker.record_success()
                return result
            except D3ProviderError as exc:
                last_error = exc
                retryable_failure = exc.retryable
                logger.warning(
                    "egress.d3.provider_error",
                    trace_id=trace_id,
                    attempt=attempt,
                    retryable=exc.retryable,
                    error=str(exc),
                    msg="D3 provider error",
                )
            except asyncio.TimeoutError:
                last_error = TimeoutError(
                    f"D3 call timed out after {settings.D3_TIMEOUT_SEC}s"
                )
                retryable_failure = True
                logger.warning(
                    "egress.d3.timeout",
                    trace_id=trace_id,
                    attempt=attempt,
                    timeout_sec=settings.D3_TIMEOUT_SEC,
                    msg="D3 call timed out",
                )
            except Exception as exc:  # non-retryable/unexpected
                last_error = exc
                retryable_failure = False
                logger.error(
                    "egress.d3.unexpected_error",
                    trace_id=trace_id,
                    attempt=attempt,
                    error_class=type(exc).__name__,
                    error=str(exc),
                    msg="Unexpected D3 provider error",
                )

            if not retryable_failure or attempt >= max_attempts:
                break

            delay = settings.D3_RETRY_BASE_DELAY_SEC * (2 ** (attempt - 1))
            logger.info(
                "egress.d3.retry",
                trace_id=trace_id,
                attempt=attempt,
                next_delay_sec=round(delay, 3),
                msg="Retrying D3 call with backoff",
            )
            await asyncio.sleep(delay)

        self.breaker.record_failure()
        raise D3CallError(
            f"D3 downstream call failed after {attempt} attempt(s): {last_error}"
        ) from last_error


d3_client = D3Client()
