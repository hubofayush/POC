"""
tests/test_denied_topics.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for Layer 4 – DeniedTopicGuard (configurable deny-list).
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.core.guardrails.ingress.layer4_content import DeniedTopicGuard

ADMIN_USER = {"sub": "admin_01", "role": "admin", "org": "test_org"}
CLEAN_CONTEXT = {"consent_granted": True}


class TestDeniedTopicGuard:

    @pytest.mark.asyncio
    async def test_denied_keyword_blocks(self):
        guard = DeniedTopicGuard()
        guard.denied = ["election", "politics"]
        result = await guard.check(
            "What is the politics of licensing boards?", CLEAN_CONTEXT, ADMIN_USER
        )
        assert result.passed is False
        assert result.code == "DENIED_TOPIC"
        assert result.details["denied_topics"] == ["politics"]

    @pytest.mark.asyncio
    async def test_clean_input_passes(self):
        guard = DeniedTopicGuard()
        guard.denied = ["election", "politics"]
        result = await guard.check(
            "Is nurse John Doe's RN license current?", CLEAN_CONTEXT, ADMIN_USER
        )
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_empty_deny_list_passes_always(self):
        guard = DeniedTopicGuard()
        guard.denied = []
        result = await guard.check("anything at all", CLEAN_CONTEXT, ADMIN_USER)
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_case_insensitive_match(self):
        guard = DeniedTopicGuard()
        guard.denied = ["election"]
        result = await guard.check("ELECTION results please", CLEAN_CONTEXT, ADMIN_USER)
        assert result.passed is False