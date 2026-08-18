"""
stage3_semantic.semantic_injection_guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 3 — Semantic Embedding Injection Guard

Evaluates input text against a curated bank of 100+ injection templates using
sentence-transformers (all-MiniLM-L6-v2) cosine similarity.

Attack-resistance improvements over the old layer2_semantic.py:

  1. 100+ templates across 8 attack categories (vs 35 before)
  2. Clause-level splitting — evaluates full text AND each clause independently
     to defeat conjunction-dilution attacks ("legit text AND ignore all rules")
  3. Sliding window — for long inputs, overlapping 25-token windows are evaluated
     so injection buried mid-paragraph is still caught
  4. All evaluations share a single pre-encoded template matrix (no per-request encoding)
"""
from __future__ import annotations

import re
from typing import Any

import torch
from sentence_transformers import SentenceTransformer, util

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.guardrails.ingress.stage3_semantic.templates import INJECTION_TEMPLATES
from app.core.logging import get_logger

logger = get_logger(__name__)

_CLAUSE_SPLIT_RE = re.compile(r"[,;.\n]|\band\b|\bor\b|\bbut\b|\bthen\b", re.IGNORECASE)


def _build_candidates(input_text: str, window_size: int = 25, stride: int = 10) -> list[str]:
    """
    Generates all candidate strings to evaluate:
      - The full input text
      - Each clause (split by conjunctions and punctuation)
      - Overlapping sliding windows of `window_size` tokens for long inputs
    """
    candidates: list[str] = [input_text]

    # Clause-level candidates
    clauses = [
        c.strip()
        for c in _CLAUSE_SPLIT_RE.split(input_text)
        if len(c.strip()) >= 10
    ]
    for c in clauses:
        if c not in candidates:
            candidates.append(c)

    # Sliding window candidates (for long inputs only)
    if settings.GUARDRAIL_SEMANTIC_WINDOW_ENABLED:
        tokens = input_text.split()
        ws = settings.GUARDRAIL_SEMANTIC_WINDOW_SIZE
        st = settings.GUARDRAIL_SEMANTIC_WINDOW_STRIDE
        if len(tokens) > ws:
            for i in range(0, len(tokens) - ws + 1, st):
                window_text = " ".join(tokens[i: i + ws])
                if window_text not in candidates:
                    candidates.append(window_text)

    return candidates


class SemanticInjectionGuard(BaseGuardrail):
    """
    Embedding-based prompt injection detection with clause splitting and sliding window.

    Pre-loads all-MiniLM-L6-v2 and pre-encodes 100+ injection templates at startup
    to keep per-request latency under ~20ms.
    """
    name = "semantic_injection"

    def __init__(self) -> None:
        self.enabled = settings.GUARDRAIL_SEMANTIC_ENABLED
        self.model_name = settings.GUARDRAIL_SEMANTIC_MODEL
        self.threshold = settings.GUARDRAIL_SEMANTIC_THRESHOLD
        self.mode = settings.GUARDRAIL_SEMANTIC_MODE

        if self.enabled:
            logger.info("guardrail.semantic.loading_model", model=self.model_name)
            self.model = SentenceTransformer(self.model_name)
            logger.info(
                "guardrail.semantic.encoding_templates",
                count=len(INJECTION_TEMPLATES),
            )
            self.template_embeddings = self.model.encode(
                INJECTION_TEMPLATES,
                convert_to_tensor=True,
                normalize_embeddings=True,
            )
            logger.info(
                "guardrail.semantic.ready",
                threshold=self.threshold,
                templates=len(INJECTION_TEMPLATES),
            )

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if not self.enabled:
            return PASS

        if len(input_text.strip()) < 10:
            return PASS

        # Build all candidate strings to evaluate
        candidates = _build_candidates(
            input_text,
            window_size=settings.GUARDRAIL_SEMANTIC_WINDOW_SIZE,
            stride=settings.GUARDRAIL_SEMANTIC_WINDOW_STRIDE,
        )

        # Batch-encode all candidates in one pass (efficient)
        input_embeddings = self.model.encode(
            candidates,
            convert_to_tensor=True,
            normalize_embeddings=True,
        )

        # Cosine similarity matrix: (num_candidates × num_templates)
        sim_matrix = util.cos_sim(input_embeddings, self.template_embeddings)
        max_flat_idx = int(torch.argmax(sim_matrix).item())
        cand_idx = max_flat_idx // len(INJECTION_TEMPLATES)
        template_idx = max_flat_idx % len(INJECTION_TEMPLATES)

        max_score = float(sim_matrix[cand_idx][template_idx])
        matched_template = INJECTION_TEMPLATES[template_idx]
        matched_candidate = candidates[cand_idx]

        if max_score >= self.threshold:
            details = {
                "matched_template": matched_template,
                "matched_candidate": matched_candidate[:120],
                "similarity_score": round(max_score, 4),
                "threshold": self.threshold,
                "model": self.model_name,
                "total_candidates_evaluated": len(candidates),
            }

            if self.mode == "block":
                logger.warning(
                    "guardrail.semantic.blocked",
                    user_id=user.get("sub"),
                    **{k: v for k, v in details.items() if k != "matched_candidate"},
                )
                return GuardrailResult(
                    passed=False,
                    code="SEMANTIC_INJECTION_DETECTED",
                    message=(
                        f"Request rejected: semantic prompt injection detected "
                        f"(similarity: {max_score:.2f} >= threshold {self.threshold:.2f})."
                    ),
                    layer="ingress.stage3.semantic_injection",
                    details=details,
                )
            else:
                logger.warning("guardrail.semantic.warn", user_id=user.get("sub"), **details)
                return GuardrailResult(
                    passed=True,
                    code="SEMANTIC_INJECTION_WARNED",
                    message=f"Semantic injection warning (similarity: {max_score:.2f}).",
                    layer="ingress.stage3.semantic_injection",
                    details=details,
                )

        return PASS
