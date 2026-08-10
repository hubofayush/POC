"""
app.core.guardrails
~~~~~~~~~~~~~~~~~~~
Production-level ingress & egress guardrail pipelines.

Structure
---------
  app/core/guardrails/
  ├── base.py          – shared types (GuardrailResult, GuardrailException,
  │                      BaseGuardrail, GuardrailPipeline)
  ├── ingress/         – pre-flight checks on every incoming REQUEST
  │   ├── pipeline.py  – ingress_pipeline singleton
  │   ├── layer1_schema.py
  │   ├── layer2_security.py
  │   ├── layer3_policy.py
  │   ├── layer4_content.py
  │   └── layer5_llm.py
  └── egress/          – post-flight checks on every LLM RESPONSE
      ├── pipeline.py  – egress_pipeline singleton
      ├── layer1_structure.py
      ├── layer2_phi.py
      ├── layer3_grounding.py
      ├── layer4_policy.py
      └── layer5_llm.py

Canonical imports
-----------------
    # Shared exception / result types
    from app.core.guardrails import GuardrailException, GuardrailResult

    # Pipeline singletons
    from app.core.guardrails.ingress import ingress_pipeline
    from app.core.guardrails.egress  import egress_pipeline

    # Individual guards (for unit testing / custom pipelines)
    from app.core.guardrails.ingress.layer2_security import PromptInjectionGuard
    from app.core.guardrails.egress.layer2_phi       import PHILeakGuard
"""
from app.core.guardrails.base import GuardrailException, GuardrailResult  # noqa: F401

__all__ = ["GuardrailException", "GuardrailResult"]
