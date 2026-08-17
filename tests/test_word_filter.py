"""
tests/test_word_filter.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Word-filter tests: ingress blocking + egress masking (both directions).
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.core.guardrails.egress.layer4_wordlist import ProfanityMaskGuard
from app.core.guardrails.ingress.layer2_wordlist import WordFilterGuard

ADMIN_USER = {"sub": "admin_01", "role": "admin", "org": "test_org"}
CLEAN_CONTEXT = {"consent_granted": True}


class TestWordFilterIngress:

    @pytest.mark.asyncio
    async def test_profanity_blocks_input(self):
        result = await WordFilterGuard().check(
            "this fucking process is broken", CLEAN_CONTEXT, ADMIN_USER
        )
        assert result.passed is False
        assert result.code == "BLOCKED_WORD_IN_INPUT"
        assert "fucking" in result.details["blocked_words"]

    @pytest.mark.asyncio
    async def test_clean_input_passes(self):
        result = await WordFilterGuard().check(
            "Is nurse John Doe's RN license current?", CLEAN_CONTEXT, ADMIN_USER
        )
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_word_boundary_no_false_positive(self):
        result = await WordFilterGuard().check(
            "the assassin was caught in scunthorpe", CLEAN_CONTEXT, ADMIN_USER
        )
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_leetspeak_bypass_blocked(self):
        result = await WordFilterGuard().check(
            "this process is fuck1ng broken", CLEAN_CONTEXT, ADMIN_USER
        )
        assert result.passed is False
        assert "fucking" in result.details["blocked_words"]


class TestProfanityMaskEgress:

    @pytest.mark.asyncio
    async def test_masks_profanity_in_output(self):
        context = {}
        guard = ProfanityMaskGuard()
        result = await guard.check(
            "That is a shit approach to billing", context, ADMIN_USER
        )
        assert result.passed is True
        assert result.code == "EGRESS_PROFANITY_MASKED"
        assert "shit" not in context["_filtered_output"]
        assert "[FILTERED]" in context["_filtered_output"]

    @pytest.mark.asyncio
    async def test_clean_output_passes_unchanged(self):
        context = {}
        result = await ProfanityMaskGuard().check(
            "The license expires March 12.", context, ADMIN_USER
        )
        assert result.passed is True
        assert "_filtered_output" not in context

    @pytest.mark.asyncio
    async def test_case_insensitive(self):
        context = {}
        guard = ProfanityMaskGuard()
        await guard.check("WHAT THE SHIT IS THIS", context, ADMIN_USER)
        assert "SHIT" not in context["_filtered_output"]

    @pytest.mark.asyncio
    async def test_chains_on_rbac_output(self):
        context = {"_filtered_output": "pre-redacted shit text"}
        await ProfanityMaskGuard().check(context["_filtered_output"], context, ADMIN_USER)
        assert "shit" not in context["_filtered_output"]
        assert "pre-redacted" in context["_filtered_output"]

    @pytest.mark.asyncio
    async def test_disabled_by_config(self, monkeypatch):
        monkeypatch.setattr(settings, "GUARDRAIL_WORD_FILTER_ENABLED", False)
        context = {}
        await ProfanityMaskGuard().check("shit", context, ADMIN_USER)
        assert "_filtered_output" not in context