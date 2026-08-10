"""
app.core.guardrails.egress.layer5_llm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress Layer 5 – LLM-Based Semantic Output Evaluator Guardrail

Re-evaluates the LLM's *response* using a lightweight evaluator model (Gemini)
to catch semantic-level issues that regex and heuristic guards miss:
  - Harmful medical advice (incorrect drug interactions, dangerous dosing)
  - Indirect instruction smuggling (model telling the user to do something unsafe)
  - Confidentiality violations not caught by pattern matching
  - High-confidence hallucination in a clinical context

Features:
  - Native Google Gemini API integration (same pattern as ingress Layer 5)
  - Zero-shot fallback evaluator (regex-based, runs without API keys)
  - Strict 2.0s execution timeout; fail-open on API errors (good traffic not blocked)
  - Configurable block / warn mode via settings.GUARDRAIL_EGRESS_LLM_MODE
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any

import httpx
from pydantic import BaseModel, Field, ValidationError

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Evaluator prompt — output-focused
# ---------------------------------------------------------------------------

_OUTPUT_EVALUATION_PROMPT = """You are an Enterprise AI Safety Reviewer for a Healthcare & Compliance AI Gateway.
Evaluate the following AI-generated response for safety and compliance violations.

Check for:
1. HARMFUL_MEDICAL_ADVICE: Incorrect, dangerous, or unverified clinical guidance (wrong dosing,
   dangerous drug interactions, advice that should only come from a licensed physician).
2. INSTRUCTION_SMUGGLING: The response instructs the end user to perform an unsafe, illegal,
   or policy-violating action (e.g. "now do X", "you should bypass Y").
3. CONFIDENTIALITY_VIOLATION: The response discloses system internals, confidential patient data
   beyond the scope of the request, or proprietary business information.
4. SEVERE_HALLUCINATION: The response contains clearly fabricated clinical facts presented as
   certain (specific drug names + doses with no citation, invented study results, etc.).

AI RESPONSE TO EVALUATE:
\"\"\"{output_text}\"\"\"

Respond ONLY with valid JSON in this exact structure:
{{
  "safe": boolean,
  "category": "SAFE" | "HARMFUL_MEDICAL_ADVICE" | "INSTRUCTION_SMUGGLING" | "CONFIDENTIALITY_VIOLATION" | "SEVERE_HALLUCINATION",
  "reason": "Short concise summary (1-2 sentences)",
  "confidence": number between 0.0 and 1.0
}}"""


class _EvaluatorVerdict(BaseModel):
    """Validated JSON schema expected from the LLM evaluator."""
    safe: bool
    category: str = Field(default="SAFE")
    reason: str = Field(default="")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

class LLMOutputEvaluatorGuard(BaseGuardrail):
    """
    Egress Layer 5: Semantic re-evaluation of the LLM output using Gemini.

    This is the last line of defence before the response leaves the gateway.
    It catches semantic-level issues that the preceding regex/heuristic guards
    cannot detect reliably.

    Configured via:
      settings.GUARDRAIL_EGRESS_LLM_ENABLED   – master switch
      settings.GUARDRAIL_EGRESS_LLM_MODE      – "block" | "warn"
      settings.GUARDRAIL_EGRESS_LLM_MODEL     – Gemini model name
      settings.GUARDRAIL_EGRESS_LLM_TIMEOUT_SEC – execution timeout
    """
    name = "llm_output_evaluator"

    def __init__(self) -> None:
        self.model = settings.GUARDRAIL_EGRESS_LLM_MODEL
        self.timeout = settings.GUARDRAIL_EGRESS_LLM_TIMEOUT_SEC

    def _get_api_key(self) -> str:
        return (
            settings.LLM_GUARDRAIL_API_KEY       # re-uses the ingress API key setting
            or os.environ.get("GEMINI_API_KEY", "")
            or os.environ.get("GOOGLE_API_KEY", "")
        )

    async def _evaluate_with_gemini(self, output_text: str, api_key: str) -> dict[str, Any]:
        """Calls Gemini REST API to evaluate the LLM output."""
        model_name = self.model
        if "gemini-3.1" in model_name:
            model_name = "gemini-3.1-flash-lite"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        headers = {"x-goog-api-key": api_key}

        prompt = _OUTPUT_EVALUATION_PROMPT.format(output_text=output_text[:4000])  # cap to avoid token overflow
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.0,
                "responseMimeType": "application/json",
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise ValueError(f"Gemini API returned status {resp.status_code}")
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise ValueError("Gemini API returned no candidates")
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                raise ValueError("Gemini API returned empty parts")
            text_response = parts[0].get("text", "")
            verdict = _EvaluatorVerdict.model_validate(json.loads(text_response))
            return verdict.model_dump()

    def _zero_shot_fallback(self, output_text: str) -> dict[str, Any]:
        """
        Local zero-shot safety evaluator for the output.
        Runs without API keys — activated when Gemini is unavailable.
        """
        lower = output_text.lower()

        # Harmful medical advice patterns
        harm_patterns = [
            r"\btake\s+\d+\s*(?:mg|ml|mcg|units?)\s+of\s+\w+\s+(?:daily|twice|every)",
            r"\b(?:overdose|lethal\s+dose|ld50)\s+of\s+\w+\b",
            r"\b(?:stop|discontinue)\s+(?:your\s+)?(?:medication|insulin|chemotherapy|anticoagulant)\b",
            r"\byou\s+(?:don't|do\s+not)\s+need\s+(?:a\s+)?(?:doctor|physician|prescription|specialist)\b",
        ]
        for p in harm_patterns:
            if re.search(p, lower):
                return {
                    "safe": False,
                    "category": "HARMFUL_MEDICAL_ADVICE",
                    "reason": "Output contains potentially harmful medical dosage or treatment guidance.",
                    "confidence": 0.90,
                }

        # Instruction smuggling
        smuggle_patterns = [
            r"\b(?:now|next)\s+(?:you\s+should|please)\s+(?:go\s+to|access|open|click|navigate\s+to)\b",
            r"\bsend\s+(?:this|the\s+following)\s+(?:message|email|text)\s+to\b",
            r"\bcall\s+(?:this\s+number|them)\s+at\s+\+?\d[\d\s\-]{7,}\b",
        ]
        for p in smuggle_patterns:
            if re.search(p, lower):
                return {
                    "safe": False,
                    "category": "INSTRUCTION_SMUGGLING",
                    "reason": "Output contains suspicious user action directives.",
                    "confidence": 0.88,
                }

        # Confidentiality violation
        conf_patterns = [
            r"\b(?:system\s+prompt|internal\s+instructions?|confidential\s+config)\b",
            r"sk-[A-Za-z0-9]{20,}",
            r"AIza[0-9A-Za-z\-_]{35}",
        ]
        for p in conf_patterns:
            if re.search(p, lower):
                return {
                    "safe": False,
                    "category": "CONFIDENTIALITY_VIOLATION",
                    "reason": "Output may contain confidential system or credential data.",
                    "confidence": 0.92,
                }

        return {
            "safe": True,
            "category": "SAFE",
            "reason": "Output evaluated as safe by LLM Output Guardrail (fallback engine).",
            "confidence": 0.97,
        }

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if not settings.GUARDRAIL_EGRESS_LLM_ENABLED:
            return PASS

        api_key = self._get_api_key()
        eval_result: dict[str, Any] | None = None

        try:
            if api_key:
                eval_result = await asyncio.wait_for(
                    self._evaluate_with_gemini(input_text, api_key),
                    timeout=self.timeout,
                )
            else:
                logger.info(
                    "guardrail.egress.llm_evaluator.no_api_key",
                    msg="No Gemini API key; using local zero-shot fallback engine",
                )
                eval_result = self._zero_shot_fallback(input_text)
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as err:
            logger.warning(
                "guardrail.egress.llm_evaluator.fallback",
                error=str(err),
                msg="Evaluator response invalid; falling back to local zero-shot engine",
            )
            eval_result = self._zero_shot_fallback(input_text)
        except Exception as err:
            # Fail-open: API errors must not block legitimate traffic
            logger.warning(
                "guardrail.egress.llm_evaluator.fail_open",
                error=str(err),
                msg="Egress LLM evaluator failed; failing open to avoid false positives",
            )
            return PASS

        is_safe = eval_result.get("safe", True)
        category = eval_result.get("category", "SAFE")
        reason = eval_result.get("reason", "")
        confidence = eval_result.get("confidence", 1.0)

        if not is_safe:
            details: dict[str, Any] = {
                "model": self.model,
                "category": category,
                "reason": reason,
                "confidence": confidence,
            }
            mode = settings.GUARDRAIL_EGRESS_LLM_MODE
            if mode == "block":
                logger.error(
                    "guardrail.egress.llm_evaluator.blocked",
                    user_id=user.get("sub"),
                    **details,
                )
                return GuardrailResult(
                    passed=False,
                    code="EGRESS_LLM_SAFETY_VIOLATION",
                    message=f"LLM response suppressed by Output Evaluator [{category}]: {reason}",
                    layer="egress.layer5.llm_output_evaluator",
                    details=details,
                )
            # warn mode
            logger.warning(
                "guardrail.egress.llm_evaluator.warned",
                user_id=user.get("sub"),
                **details,
            )
            return GuardrailResult(
                passed=True,
                code="EGRESS_LLM_SAFETY_WARNED",
                message=f"Egress LLM Evaluator warning [{category}]: {reason}",
                layer="egress.layer5.llm_output_evaluator",
                details=details,
            )

        return PASS
