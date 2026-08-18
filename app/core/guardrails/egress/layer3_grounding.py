"""
app.core.guardrails.egress.layer3_grounding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Egress Layer 3 – Hallucination & Citation Grounding Guards

Checks that the LLM's output is grounded in the citations it returned and
does not contain recognisable hallucination patterns.

Guards (in execution order):
  1. CitationCoverageGuard    – verifies meaningful term overlap between the
                                response body and the provided citations list
  2. HallucinationPatternGuard – regex-based detection of known hallucination
                                  language patterns (fabricated stats, absolute
                                  clinical claims, knowledge-cutoff hedges in
                                  a real-time health context)

Both guards support warn/block mode via settings.GUARDRAIL_EGRESS_GROUNDING_MODE.

Note on grounding depth
-----------------------
This implementation uses term-overlap heuristics (not embedding similarity).
It is intentionally lightweight — sufficient for production alerting without
requiring a vector store dependency. Embedding-based grounding can be layered
on top as a future enhancement.
"""
from __future__ import annotations

import re
from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_key_terms(text: str, min_len: int = 5) -> set[str]:
    """
    Extract candidate key terms from text:
    - Alphabetic tokens of meaningful length (≥ min_len chars)
    - All-caps acronyms (≥ 2 chars) — likely clinical codes / drug names
    Returns a lower-cased set for overlap comparison.
    """
    words = re.findall(r"\b[A-Za-z]{%d,}\b" % min_len, text)
    acronyms = re.findall(r"\b[A-Z]{2,}\b", text)
    return {w.lower() for w in words + acronyms}


# ---------------------------------------------------------------------------
# 1. Citation Coverage Guard
# ---------------------------------------------------------------------------

# Minimum fraction of output key terms that must appear in citations
_MIN_COVERAGE_RATIO = 0.05      # 5% of output terms must exist in citations
_MIN_OUTPUT_LEN_FOR_CHECK = 80  # Skip very short outputs (too ambiguous)
_MIN_CITATIONS_FOR_CHECK = 1    # Need at least one citation to do coverage check


class CitationCoverageGuard(BaseGuardrail):
    """
    Verifies that the LLM's output is meaningfully grounded in its citations.

    Strategy:
    - Extract key terms from the output body.
    - Check what fraction of those terms also appear in the citations string.
    - If coverage is below the threshold AND at least one citation was provided,
      warn/block depending on mode.

    When no citations are provided at all, a warning is always emitted
    regardless of mode (uncited output is always flagged).
    """
    name = "citation_coverage"

    def __init__(self, min_coverage_ratio: float = _MIN_COVERAGE_RATIO) -> None:
        self._min_ratio = min_coverage_ratio

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        # Citations are injected into the context by run_egress_guardrails()
        citations: list[str] = context.get("_egress_citations", [])

        if len(input_text) < _MIN_OUTPUT_LEN_FOR_CHECK:
            return PASS

        # Case 1: no citations at all
        if not citations:
            msg = (
                "LLM output has no supporting citations. "
                "Output may not be grounded in verified source material."
            )
            details: dict[str, Any] = {"citation_count": 0, "output_length": len(input_text)}
            logger.warning("guardrail.egress.citation_coverage.no_citations",
                           user_id=user.get("sub"), **details)
            # Always warn on zero citations (never block — it would reject all un-cited outputs)
            return GuardrailResult(
                passed=True,
                code="EGRESS_UNCITED_OUTPUT",
                message=msg,
                layer="egress.layer3.citation_coverage",
                details=details,
            )

        # Case 2: citations exist — check term overlap
        citation_texts: list[str] = []
        for c in citations:
            if isinstance(c, str):
                citation_texts.append(c)
            elif isinstance(c, dict):
                file_name = str(c.get("file_name") or c.get("filename") or "")
                page = str(c.get("page") or c.get("page_number") or "")
                chunk_id = str(c.get("chunk_id") or c.get("chunk_name") or c.get("chunk") or "")
                text_content = str(c.get("text") or c.get("content") or "")
                parts = [p for p in [file_name, page, chunk_id, text_content] if p]
                citation_texts.append(" ".join(parts))
            elif hasattr(c, "model_dump"):
                d = c.model_dump()
                parts = [str(v) for v in d.values() if v is not None]
                citation_texts.append(" ".join(parts))
            else:
                citation_texts.append(str(c))

        citations_blob = " ".join(citation_texts).lower()
        output_terms = _extract_key_terms(input_text)

        if not output_terms:
            return PASS

        covered = sum(1 for t in output_terms if t in citations_blob)
        ratio = covered / len(output_terms)

        if ratio >= self._min_ratio:
            return PASS

        msg = (
            f"LLM output has low citation coverage "
            f"({ratio:.1%} of key terms found in citations, "
            f"threshold: {self._min_ratio:.1%})."
        )
        details = {
            "coverage_ratio": round(ratio, 4),
            "threshold": self._min_ratio,
            "output_terms_checked": len(output_terms),
            "citation_count": len(citations),
        }

        mode = settings.GUARDRAIL_EGRESS_GROUNDING_MODE
        if mode == "block":
            return GuardrailResult(
                passed=False,
                code="EGRESS_LOW_CITATION_COVERAGE",
                message=msg,
                layer="egress.layer3.citation_coverage",
                details=details,
            )
        logger.warning("guardrail.egress.citation_coverage.warn",
                       user_id=user.get("sub"), **details)
        return GuardrailResult(
            passed=True,
            code="EGRESS_LOW_CITATION_COVERAGE_WARNED",
            message=msg,
            layer="egress.layer3.citation_coverage",
            details=details,
        )


# ---------------------------------------------------------------------------
# 2. Hallucination Pattern Guard
# ---------------------------------------------------------------------------

# Fabricated / inflated statistics: "studies show 87%", "100% of patients"
_FAKE_STAT_RE = re.compile(
    r"(?:"
    r"studies?\s+show\s+\d[\d,.]*\s*%"
    r"|research\s+(?:shows?|confirms?|proves?)\s+\d[\d,.]*\s*%"
    r"|(?:100|0)\s*%\s+of\s+(?:patients?|cases?|individuals?|providers?)"
    r"|\d[\d,.]*\s*%\s+of\s+(?:all\s+)?(?:patients?|cases?|studies?)"
    r")",
    re.IGNORECASE,
)

# Absolute clinical claims without hedging
_ABSOLUTE_CLINICAL_RE = re.compile(
    r"\b(?:always|never|guaranteed|definitely|certainly|proven\s+to)\b"
    r"\s+.{0,60}"
    r"(?:cure|treat|prevent|diagnose|cause|work|effective|safe)\b",
    re.IGNORECASE | re.DOTALL,
)

# Knowledge-cutoff hedge in a context that implies real-time capability
_KNOWLEDGE_CUTOFF_RE = re.compile(
    r"as\s+of\s+my\s+(?:knowledge\s+)?(?:cutoff|training|last\s+update)",
    re.IGNORECASE,
)

# AI self-identification leaking into a clinical / authoritative response
_AI_HEDGING_RE = re.compile(
    r"(?:I\s+am\s+an?\s+(?:AI|language\s+model|LLM))",
    re.IGNORECASE,
)

_HALLUCINATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_FAKE_STAT_RE,          "fabricated_statistic"),
    (_ABSOLUTE_CLINICAL_RE,  "absolute_clinical_claim"),
    (_KNOWLEDGE_CUTOFF_RE,   "knowledge_cutoff_hedge"),
    (_AI_HEDGING_RE,         "ai_self_identification"),
]


class HallucinationPatternGuard(BaseGuardrail):
    """
    Detects common hallucination language patterns in the LLM output.

    This is a heuristic guard — it catches well-known failure modes
    (fabricated statistics, absolute clinical claims, temporal hedges)
    without requiring a separate fact-checking model.

    Mode: controlled by settings.GUARDRAIL_EGRESS_GROUNDING_MODE.
    Default is "warn": log the finding, pass the response with a metadata flag.
    """
    name = "hallucination_pattern"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        for pattern, reason in _HALLUCINATION_PATTERNS:
            match = pattern.search(input_text)
            if match:
                snippet = match.group()[:120].replace("\n", " ")
                msg = (
                    f"LLM output contains a potential hallucination pattern "
                    f"[{reason}]: '{snippet}…'"
                )
                details: dict[str, Any] = {
                    "reason": reason,
                    "snippet": snippet,
                }

                mode = settings.GUARDRAIL_EGRESS_GROUNDING_MODE
                if mode == "block":
                    return GuardrailResult(
                        passed=False,
                        code="EGRESS_HALLUCINATION_DETECTED",
                        message=msg,
                        layer="egress.layer3.hallucination_pattern",
                        details=details,
                    )
                logger.warning(
                    "guardrail.egress.hallucination.warn",
                    user_id=user.get("sub"),
                    **details,
                )
                return GuardrailResult(
                    passed=True,
                    code="EGRESS_HALLUCINATION_WARNED",
                    message=msg,
                    layer="egress.layer3.hallucination_pattern",
                    details=details,
                )

        return PASS


# ---------------------------------------------------------------------------
# 3. Semantic Grounding Guard (embedding-based)
# ---------------------------------------------------------------------------
# The docstring's "future enhancement": cosine similarity between the output
# and the citation chunks, catching paraphrased ungrounded output that
# term-overlap misses. Uses the shared MiniLM encoder cache.

from app.core.guardrails.ingress.layer2_semantic import get_encoder  # noqa: E402

_MIN_SEMANTIC_LEN = 120        # skip short outputs
_MIN_CITATIONS_SEMANTIC = 1    # need citations to ground against
_SEMANTIC_THRESHOLD = 0.55     # min best cosine similarity to consider grounded


class SemanticGroundingGuard(BaseGuardrail):
    """
    Embedding-based grounding check: output vs. citation chunks.

    Term-overlap (CitationCoverageGuard) misses paraphrases; cosine similarity
    of MiniLM embeddings catches them. Mode honors
    settings.GUARDRAIL_EGRESS_GROUNDING_MODE ("warn" | "block").
    """
    name = "semantic_grounding"

    def __init__(self) -> None:
        import torch  # noqa: F401  (ensures sentence-transformers backend ready)
        from sentence_transformers import SentenceTransformer  # noqa: F401
        self.encoder = get_encoder(settings.GUARDRAIL_SEMANTIC_MODEL)

    @staticmethod
    def _citation_blob(citations: list[Any]) -> str:
        parts: list[str] = []
        for c in citations:
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, dict):
                parts.append(
                    " ".join(
                        str(c.get(k) or "")
                        for k in ("file_name", "filename", "page", "page_number",
                                  "chunk_id", "chunk_name", "chunk", "text", "content")
                    )
                )
            else:
                parts.append(str(c))
        return " ".join(p for p in parts if p)

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        citations = context.get("_egress_citations", [])
        if len(input_text) < _MIN_SEMANTIC_LEN or len(citations) < _MIN_CITATIONS_SEMANTIC:
            return PASS

        import torch
        from sentence_transformers import util

        blob = self._citation_blob(citations)
        if not blob.strip():
            return PASS

        # Cap citation blob to avoid embedding oversized text
        out_emb = self.encoder.encode(
            input_text, convert_to_tensor=True, normalize_embeddings=True
        )
        cit_emb = self.encoder.encode(
            blob[:8000], convert_to_tensor=True, normalize_embeddings=True
        )
        score = float(util.cos_sim(out_emb, cit_emb)[0][0])

        if score >= _SEMANTIC_THRESHOLD:
            return PASS

        msg = (
            f"LLM output is semantically ungrounded in citations "
            f"(similarity {score:.3f}, threshold {_SEMANTIC_THRESHOLD})."
        )
        details = {
            "similarity_score": round(score, 4),
            "threshold": _SEMANTIC_THRESHOLD,
            "output_length": len(input_text),
            "citation_count": len(citations),
        }

        mode = settings.GUARDRAIL_EGRESS_GROUNDING_MODE
        if mode == "block":
            return GuardrailResult(
                passed=False,
                code="EGRESS_UNGROUNDED_OUTPUT",
                message=msg,
                layer="egress.layer3.semantic_grounding",
                details=details,
            )
        logger.warning(
            "guardrail.egress.semantic_grounding.warn",
            user_id=user.get("sub"),
            **details,
        )
        return GuardrailResult(
            passed=True,
            code="EGRESS_UNGROUNDED_WARNED",
            message=msg,
            layer="egress.layer3.semantic_grounding",
            details=details,
        )
