"""
app.core.guardrails
~~~~~~~~~~~~~~~~~~~
Production-level ingress guardrail pipeline.

Import the pre-built singleton pipeline via:
    from app.core.guardrails.pipeline import ingress_pipeline
"""
from app.core.guardrails.base import GuardrailResult, GuardrailException  # noqa: F401
