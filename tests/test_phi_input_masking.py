"""
tests/test_phi_input_masking.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for ingress PHI masking — raw PHI must never reach D3 payload.
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.core.guardrails.ingress.layer2_security import PHIInInputGuard

ADMIN_USER = {"sub": "admin_01", "role": "admin", "org": "test_org"}


class TestPHIInputMasking:

    @pytest.mark.asyncio
    async def test_phi_input_stashes_masked_text(self):
        context = {"consent_granted": True}
        guard = PHIInInputGuard()
        await guard.check(
            "Patient John Smith SSN 123-45-6789 needs re-credentialing",
            context, ADMIN_USER,
        )
        masked = context.get("_masked_input")
        assert masked is not None
        assert "123-45-6789" not in masked
        assert "John Smith" not in masked

    @pytest.mark.asyncio
    async def test_clean_input_no_masking_stashed(self):
        context = {"consent_granted": True}
        guard = PHIInInputGuard()
        await guard.check("Is the RN license expired?", context, ADMIN_USER)
        assert "_masked_input" not in context

    @pytest.mark.asyncio
    async def test_masking_disabled_by_config(self, monkeypatch):
        monkeypatch.setattr(settings, "GUARDRAIL_INPUT_PHI_MASK", False)
        context = {"consent_granted": True}
        guard = PHIInInputGuard()
        await guard.check(
            "Patient John Smith SSN 123-45-6789 needs re-credentialing",
            context, ADMIN_USER,
        )
        assert "_masked_input" not in context