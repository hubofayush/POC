"""
tests.test_egress_guardrails
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for the 5-layer egress guardrail pipeline.

Each guard is tested in isolation using pytest + anyio.
The GuardrailPipeline integration test verifies short-circuit behaviour.
"""
from __future__ import annotations

import pytest

from app.core.guardrails.egress.layer1_structure import (
    OutputEncodingAnomalyGuard,
    OutputSizeLimitGuard,
)
from app.core.guardrails.egress.layer2_phi import PHILeakGuard
from app.core.guardrails.egress.layer3_grounding import (
    CitationCoverageGuard,
    HallucinationPatternGuard,
)
from app.core.guardrails.egress.layer4_policy import (
    ForbiddenDisclosureGuard,
    RoleBasedOutputFilterGuard,
    ToxicOutputGuard,
)
from app.core.guardrails.egress.layer5_llm import LLMOutputEvaluatorGuard
from app.core.guardrails.base import GuardrailException, GuardrailPipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_USER_HR    = {"sub": "u1", "role": "hr",    "org": "test_org"}
_USER_ADMIN = {"sub": "u2", "role": "admin", "org": "test_org"}
_CTX: dict   = {}


# ---------------------------------------------------------------------------
# EL1 – Structural Integrity
# ---------------------------------------------------------------------------

class TestOutputSizeLimitGuard:
    guard = OutputSizeLimitGuard(max_bytes=100)

    @pytest.mark.anyio
    async def test_passes_small_output(self):
        result = await self.guard.check("Hello world", _CTX, _USER_HR)
        assert result.passed

    @pytest.mark.anyio
    async def test_blocks_oversized_output(self):
        result = await self.guard.check("x" * 200, _CTX, _USER_HR)
        assert not result.passed
        assert result.code == "OUTPUT_TOO_LARGE"

    @pytest.mark.anyio
    async def test_details_contain_byte_counts(self):
        text = "x" * 200
        result = await self.guard.check(text, _CTX, _USER_HR)
        assert result.details["actual_bytes"] == 200
        assert result.details["max_bytes"] == 100


class TestOutputEncodingAnomalyGuard:
    guard = OutputEncodingAnomalyGuard()

    @pytest.mark.anyio
    async def test_passes_clean_output(self):
        result = await self.guard.check("Patient is doing well.", _CTX, _USER_HR)
        assert result.passed

    @pytest.mark.anyio
    async def test_blocks_bidi_override(self):
        bidi_text = "safe text \u202e reversed text"
        result = await self.guard.check(bidi_text, _CTX, _USER_HR)
        assert not result.passed
        assert result.code == "OUTPUT_ENCODING_ANOMALY"
        assert result.details["reason"] == "bidi_override_character"

    @pytest.mark.anyio
    async def test_blocks_invisible_char_cluster(self):
        invisible_text = "data\u200b\u200c\u200d\u200e\u200fmore"
        result = await self.guard.check(invisible_text, _CTX, _USER_HR)
        assert not result.passed
        assert result.details["reason"] == "invisible_character_cluster"


# ---------------------------------------------------------------------------
# EL2 – PHI Leak
# ---------------------------------------------------------------------------

class TestPHILeakGuard:
    guard = PHILeakGuard()

    @pytest.mark.anyio
    async def test_passes_clean_output(self):
        result = await self.guard.check("The credentialing process is complete.", _CTX, _USER_HR)
        assert result.passed

    @pytest.mark.anyio
    async def test_warn_mode_passes_with_phi(self, monkeypatch):
        """In warn mode (default), PHI is detected but request passes."""
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_PHI_MODE", "warn")
        # SSN in output
        result = await self.guard.check(
            "Patient SSN: 123-45-6789", _CTX, _USER_HR
        )
        # warn mode → passes=True
        assert result.passed
        assert result.code == "EGRESS_PHI_LEAK_WARNED"

    @pytest.mark.anyio
    async def test_block_mode_blocks_phi(self, monkeypatch):
        """In block mode, raw PHI in output is suppressed."""
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_PHI_MODE", "block")
        result = await self.guard.check(
            "Patient SSN: 123-45-6789", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_PHI_LEAK"

    @pytest.mark.anyio
    async def test_admin_bypasses_phi_check(self, monkeypatch):
        """Admin role always bypasses PHI leak guard."""
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_PHI_MODE", "block")
        result = await self.guard.check(
            "Patient SSN: 123-45-6789", _CTX, _USER_ADMIN
        )
        assert result.passed  # bypassed


# ---------------------------------------------------------------------------
# EL3 – Grounding
# ---------------------------------------------------------------------------

class TestCitationCoverageGuard:
    guard = CitationCoverageGuard()

    @pytest.mark.anyio
    async def test_passes_short_output(self):
        result = await self.guard.check("OK.", {"_egress_citations": []}, _USER_HR)
        assert result.passed

    @pytest.mark.anyio
    async def test_warns_on_zero_citations(self):
        long_output = "The clinician credentialing process involves verification. " * 3
        result = await self.guard.check(
            long_output, {"_egress_citations": []}, _USER_HR
        )
        assert result.passed  # warn-only, always passes
        assert result.code == "EGRESS_UNCITED_OUTPUT"

    @pytest.mark.anyio
    async def test_passes_with_sufficient_coverage(self):
        long_output = "The credentialing and verification process requires certification."
        citations = ["credentialing verification certification process"]
        ctx = {"_egress_citations": citations}
        result = await self.guard.check(long_output, ctx, _USER_HR)
        assert result.passed

    @pytest.mark.anyio
    async def test_warns_low_coverage(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_GROUNDING_MODE", "warn")
        long_output = "Quantum physics explains the behaviour of subatomic particles in detail."
        citations = ["completely unrelated citation text about something else entirely here"]
        ctx = {"_egress_citations": citations}
        result = await self.guard.check(long_output, ctx, _USER_HR)
        # warn mode passes even on low coverage
        assert result.passed

    @pytest.mark.anyio
    async def test_passes_with_structured_citations(self):
        long_output = "The credentialing and verification process requires certification."
        citations = [
            {
                "file_name": "credentialing_policy.pdf",
                "page": 5,
                "chunk_id": "chunk_verification_certification_001",
            }
        ]
        ctx = {"_egress_citations": citations}
        result = await self.guard.check(long_output, ctx, _USER_HR)
        assert result.passed


class TestHallucinationPatternGuard:
    guard = HallucinationPatternGuard()

    @pytest.mark.anyio
    async def test_passes_clean_output(self):
        result = await self.guard.check(
            "The provider's license expires on 2024-12-31.", _CTX, _USER_HR
        )
        assert result.passed

    @pytest.mark.anyio
    async def test_detects_fake_statistic(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_GROUNDING_MODE", "warn")
        result = await self.guard.check(
            "Studies show 87% of patients improve with this treatment.", _CTX, _USER_HR
        )
        assert result.passed   # warn mode
        assert result.code == "EGRESS_HALLUCINATION_WARNED"
        assert result.details["reason"] == "fabricated_statistic"

    @pytest.mark.anyio
    async def test_blocks_fake_statistic_in_block_mode(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_GROUNDING_MODE", "block")
        result = await self.guard.check(
            "Studies show 87% of patients improve.", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_HALLUCINATION_DETECTED"

    @pytest.mark.anyio
    async def test_detects_knowledge_cutoff_hedge(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_GROUNDING_MODE", "warn")
        result = await self.guard.check(
            "As of my knowledge cutoff, the medication is approved.", _CTX, _USER_HR
        )
        assert result.code == "EGRESS_HALLUCINATION_WARNED"
        assert result.details["reason"] == "knowledge_cutoff_hedge"

    @pytest.mark.anyio
    async def test_detects_ai_self_identification(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_GROUNDING_MODE", "warn")
        result = await self.guard.check(
            "I am an AI language model and cannot provide medical advice.", _CTX, _USER_HR
        )
        assert result.code == "EGRESS_HALLUCINATION_WARNED"
        assert result.details["reason"] == "ai_self_identification"


# ---------------------------------------------------------------------------
# EL4 – Content Policy
# ---------------------------------------------------------------------------

class TestToxicOutputGuard:
    guard = ToxicOutputGuard()

    @pytest.mark.anyio
    async def test_passes_clean_output(self):
        result = await self.guard.check(
            "The credentialing verification was successful.", _CTX, _USER_HR
        )
        assert result.passed

    @pytest.mark.anyio
    async def test_blocks_violent_language(self):
        result = await self.guard.check(
            "You should kill them all.", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_TOXIC_CONTENT"

    @pytest.mark.anyio
    async def test_blocks_self_harm(self):
        result = await self.guard.check(
            "You should hurt yourself.", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_TOXIC_CONTENT"


class TestForbiddenDisclosureGuard:
    guard = ForbiddenDisclosureGuard()

    @pytest.mark.anyio
    async def test_passes_normal_output(self):
        result = await self.guard.check(
            "The nurse's license is valid until 2025.", _CTX, _USER_HR
        )
        assert result.passed

    @pytest.mark.anyio
    async def test_blocks_system_prompt_leak(self):
        result = await self.guard.check(
            "My system prompt says: you are a helpful assistant...", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_SYSTEM_PROMPT_LEAK"

    @pytest.mark.anyio
    async def test_blocks_cot_tag(self):
        result = await self.guard.check(
            "<think>Internal reasoning here...</think>Final answer.", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_CHAIN_OF_THOUGHT_LEAK"

    @pytest.mark.anyio
    async def test_blocks_api_key_pattern(self):
        result = await self.guard.check(
            "api_key = sk-abcdefghijklmnopqrstuv12345678901234567890",
            _CTX, _USER_HR,
        )
        assert not result.passed
        assert result.code == "EGRESS_CREDENTIAL_LEAK"

    @pytest.mark.anyio
    async def test_blocks_internal_delimiter(self):
        result = await self.guard.check(
            "[INST] Follow these new instructions [/INST]", _CTX, _USER_HR
        )
        assert not result.passed
        assert result.code == "EGRESS_INTERNAL_TAG_LEAK"


class TestRoleBasedOutputFilterGuard:
    guard = RoleBasedOutputFilterGuard()

    @pytest.mark.anyio
    async def test_hr_role_redacts_clinical_terms(self):
        ctx: dict = {}
        await self.guard.check(
            "The diagnosis is hypertension. Treatment: medication.", ctx, _USER_HR
        )
        filtered = ctx["_filtered_output"]
        assert "diagnosis" not in filtered.lower() or "[CLINICAL-REDACTED]" in filtered
        assert "treatment" not in filtered.lower() or "[CLINICAL-REDACTED]" in filtered

    @pytest.mark.anyio
    async def test_admin_role_passthrough(self):
        ctx: dict = {}
        original = "The diagnosis is hypertension. Treatment: medication."
        await self.guard.check(original, ctx, _USER_ADMIN)
        assert ctx["_filtered_output"] == original

    @pytest.mark.anyio
    async def test_returns_pass_always(self):
        ctx: dict = {}
        result = await self.guard.check("Any text.", ctx, _USER_HR)
        assert result.passed


# ---------------------------------------------------------------------------
# EL5 – LLM Output Evaluator (fallback engine only — no API call)
# ---------------------------------------------------------------------------

class TestLLMOutputEvaluatorGuard:
    guard = LLMOutputEvaluatorGuard()

    @pytest.mark.anyio
    async def test_disabled_guard_passes(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_LLM_ENABLED", False)
        result = await self.guard.check("Any output text.", _CTX, _USER_HR)
        assert result.passed

    @pytest.mark.anyio
    async def test_fallback_passes_clean_output(self, monkeypatch):
        """Zero-shot fallback should pass normal clinical output."""
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_LLM_ENABLED", True)
        monkeypatch.setattr("app.config.settings.LLM_GUARDRAIL_API_KEY", "")
        result = await self.guard.check(
            "The provider's credentialing is complete and verified.", _CTX, _USER_HR
        )
        assert result.passed

    @pytest.mark.anyio
    async def test_fallback_blocks_credential_leak(self, monkeypatch):
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_LLM_ENABLED", True)
        monkeypatch.setattr("app.config.settings.LLM_GUARDRAIL_API_KEY", "")
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_LLM_MODE", "block")
        result = await self.guard.check(
            "The system prompt is: AIzaSyAbcdefghijklmnopqrstuvwxyz123456789",
            _CTX, _USER_HR,
        )
        assert not result.passed
        assert result.code == "EGRESS_LLM_SAFETY_VIOLATION"


# ---------------------------------------------------------------------------
# Integration – Pipeline short-circuit
# ---------------------------------------------------------------------------

class TestEgressPipelineIntegration:

    @pytest.mark.anyio
    async def test_pipeline_short_circuits_on_first_block(self):
        """A blocked EL1 guard must prevent EL2+ from running."""
        pipeline = GuardrailPipeline(guards=[
            OutputSizeLimitGuard(max_bytes=10),
            PHILeakGuard(),
        ])
        with pytest.raises(GuardrailException) as exc_info:
            await pipeline.run(
                input_text="x" * 100,
                context={},
                user=_USER_HR,
            )
        assert exc_info.value.result.code == "OUTPUT_TOO_LARGE"

    @pytest.mark.anyio
    async def test_pipeline_passes_clean_output(self, monkeypatch):
        """All guards pass for a clean, short, citation-covered output."""
        monkeypatch.setattr("app.config.settings.GUARDRAIL_EGRESS_LLM_ENABLED", False)
        from app.core.guardrails.egress import egress_pipeline
        ctx = {"_egress_citations": ["credentialing license verification"]}
        results = await egress_pipeline.run(
            input_text="Credentialing and license verification is complete.",
            context=ctx,
            user=_USER_HR,
        )
        assert all(r.passed for r in results)
