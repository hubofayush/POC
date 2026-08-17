"""
tests/test_semantic_grounding.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for egress Layer 3 – SemanticGroundingGuard (embedding similarity
between LLM output and citations).
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.core.guardrails.egress.layer3_grounding import SemanticGroundingGuard

ADMIN_USER = {"sub": "admin_01", "role": "admin", "org": "test_org"}
CONTEXT = {"consent_granted": True}

CITED = ("Nurse John Doe holds an active RN license in California, issued "
         "2021-03-12, expiring 2027-03-12, verified against the state "
         "registry on 2026-08-01. No sanctions or exclusions on record.")


class TestSemanticGroundingGuard:

    @pytest.mark.asyncio
    async def test_grounded_output_passes(self):
        context = {**CONTEXT, "_egress_citations": [CITED]}
        result = await SemanticGroundingGuard().check(
            "John Doe's RN license is active and expires March 2027. "
            "It was verified against the California registry and shows no "
            "sanctions or exclusions. He is in good standing.",
            context, ADMIN_USER,
        )
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_ungrounded_output_warns_in_warn_mode(self, monkeypatch):
        monkeypatch.setattr(settings, "GUARDRAIL_EGRESS_GROUNDING_MODE", "warn")
        context = {**CONTEXT, "_egress_citations": [CITED]}
        result = await SemanticGroundingGuard().check(
            "The hospital's lunar surface credentialing program was certified "
            "on Saturn orbit station, with a 92% pass rate across all "
            "interstellar units. Certification is fully approved.",
            context, ADMIN_USER,
        )
        assert result.passed is True
        assert result.code == "EGRESS_UNGROUNDED_WARNED"
        assert result.details["similarity_score"] < 0.55

    @pytest.mark.asyncio
    async def test_ungrounded_blocks_in_block_mode(self, monkeypatch):
        monkeypatch.setattr(settings, "GUARDRAIL_EGRESS_GROUNDING_MODE", "block")
        context = {**CONTEXT, "_egress_citations": [CITED]}
        result = await SemanticGroundingGuard().check(
            "The hospital's lunar surface credentialing program was certified "
            "on Saturn orbit station, with a 92% pass rate across all "
            "interstellar units. Certification is fully approved.",
            context, ADMIN_USER,
        )
        assert result.passed is False
        assert result.code == "EGRESS_UNGROUNDED_OUTPUT"

    @pytest.mark.asyncio
    async def test_short_output_skipped(self):
        context = {**CONTEXT, "_egress_citations": [CITED]}
        result = await SemanticGroundingGuard().check(
            "License is active.", context, ADMIN_USER
        )
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_no_citations_skipped(self):
        result = await SemanticGroundingGuard().check(
            "Some sufficiently long output here that would otherwise be "
            "checked for grounding but there are no citations at all so it "
            "must be skipped without evaluation.",
            {**CONTEXT, "_egress_citations": []}, ADMIN_USER,
        )
        assert result.passed is True