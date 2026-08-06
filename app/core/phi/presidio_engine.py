"""
app.core.phi.presidio_engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Microsoft Presidio PII/PHI Detection Engine — Singleton & Custom Recognizers.

Wraps presidio_analyzer.AnalyzerEngine and presidio_anonymizer.AnonymizerEngine
as lazy-initialized singletons (expensive to create per-request).

Custom Healthcare Recognizers added on top of Presidio built-ins:
  - NPI           (10-digit National Provider Identifier)
  - DEA_NUMBER    (2 letters + 7 digits Drug Enforcement Admin number)
  - MEDICAL_RECORD_NUMBER  (MRN / PID / PATIENT-ID + digits)
  - PROVIDER_LICENSE       (RN/MD/DO/LPN/PA – followed by digits)

Usage:
    from app.core.phi.presidio_engine import analyze_pii, anonymize_pii

    findings = analyze_pii("Patient John Smith SSN: 123-45-6789")
    masked   = anonymize_pii("Patient John Smith SSN: 123-45-6789")
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Lazy-loaded imports — Presidio is optional; fail gracefully if not installed
# ---------------------------------------------------------------------------
try:
    from presidio_analyzer import (
        AnalyzerEngine,
        Pattern,
        PatternRecognizer,
        RecognizerRegistry,
    )
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig

    _PRESIDIO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PRESIDIO_AVAILABLE = False
    logger.warning("presidio.unavailable", msg="presidio_analyzer not installed; PII engine disabled.")


# ---------------------------------------------------------------------------
# Result dataclass (mirrors PHIFinding for easy merging)
# ---------------------------------------------------------------------------

@dataclass
class PresidioFinding:
    """A single PII/PHI finding returned by Presidio."""
    type: str           # e.g. "PERSON", "EMAIL_ADDRESS", "NPI"
    value: str          # The matched text
    start: int          # Character offset (inclusive)
    end: int            # Character offset (exclusive)
    score: float        # Confidence score 0.0–1.0


# ---------------------------------------------------------------------------
# Custom Healthcare Pattern Recognizers
# ---------------------------------------------------------------------------

def _build_npi_recognizer() -> PatternRecognizer:
    """10-digit National Provider Identifier."""
    return PatternRecognizer(
        supported_entity="NPI",
        name="NPI Recognizer",
        patterns=[
            Pattern(
                name="npi_pattern",
                regex=r"\b(?:NPI[:\s]*)?\d{10}\b",
                score=0.85,
            )
        ],
        context=["npi", "national provider", "provider id", "provider identifier"],
    )


def _build_dea_recognizer() -> PatternRecognizer:
    """DEA Registration Number: 2 letters + 7 digits."""
    return PatternRecognizer(
        supported_entity="DEA_NUMBER",
        name="DEA Number Recognizer",
        patterns=[
            Pattern(
                name="dea_pattern",
                regex=r"\b(?:DEA[:\s]*)?[A-Z]{2}\d{7}\b",
                score=0.90,
            )
        ],
        context=["dea", "drug enforcement", "schedule", "controlled substance"],
    )


def _build_mrn_recognizer() -> PatternRecognizer:
    """Medical Record Number / Patient ID."""
    return PatternRecognizer(
        supported_entity="MEDICAL_RECORD_NUMBER",
        name="MRN Recognizer",
        patterns=[
            Pattern(
                name="mrn_pattern",
                regex=r"\b(?:MRN|PID|PATIENT[- ]?ID)[:\s]*\d{5,}\b",
                score=0.95,
            )
        ],
        context=["mrn", "medical record", "patient id", "patient number", "chart"],
    )


def _build_provider_license_recognizer() -> PatternRecognizer:
    """Provider License: RN/MD/DO/LPN/PA followed by digits."""
    return PatternRecognizer(
        supported_entity="PROVIDER_LICENSE",
        name="Provider License Recognizer",
        patterns=[
            Pattern(
                name="license_pattern",
                regex=r"\b(?:RN|MD|DO|LPN|PA)[-]?\d{5,}\b",
                score=0.85,
            )
        ],
        context=["license", "licence", "credential", "provider", "registration"],
    )


# ---------------------------------------------------------------------------
# Entity list — all entities to detect in analyze()
# ---------------------------------------------------------------------------

PRESIDIO_ENTITIES: list[str] = [
    # ── Built-in Presidio entities ──
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "LOCATION",
    "DATE_TIME",
    "URL",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "MEDICAL_LICENSE",
    # ── Custom healthcare entities ──
    "NPI",
    "DEA_NUMBER",
    "MEDICAL_RECORD_NUMBER",
    "PROVIDER_LICENSE",
]


# ---------------------------------------------------------------------------
# Singleton engine initialization
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


def _build_analyzer() -> AnalyzerEngine:
    """Build and return a configured AnalyzerEngine with NLP + custom recognizers."""
    # Configure NLP engine (spaCy)
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": "en", "model_name": settings.PRESIDIO_NLP_MODEL}
        ],
    }
    provider = NlpEngineProvider(nlp_configuration=nlp_config)
    nlp_engine = provider.create_engine()

    # Build registry with built-in + custom recognizers
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    # Add custom healthcare recognizers
    registry.add_recognizer(_build_npi_recognizer())
    registry.add_recognizer(_build_dea_recognizer())
    registry.add_recognizer(_build_mrn_recognizer())
    registry.add_recognizer(_build_provider_license_recognizer())

    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
    )
    logger.info(
        "presidio.analyzer.initialized",
        nlp_model=settings.PRESIDIO_NLP_MODEL,
        recognizers=len(list(registry.recognizers)),
    )
    return analyzer


def _get_analyzer() -> AnalyzerEngine:
    """Thread-safe lazy singleton for AnalyzerEngine."""
    global _analyzer
    if _analyzer is None:
        with _lock:
            if _analyzer is None:
                _analyzer = _build_analyzer()
    return _analyzer


def _get_anonymizer() -> AnonymizerEngine:
    """Thread-safe lazy singleton for AnonymizerEngine."""
    global _anonymizer
    if _anonymizer is None:
        with _lock:
            if _anonymizer is None:
                _anonymizer = AnonymizerEngine()
    return _anonymizer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_pii(text: str) -> list[PresidioFinding]:
    """
    Detect PII/PHI in text using Presidio AnalyzerEngine.

    Returns a list of PresidioFinding instances ordered by start position,
    filtered by settings.PRESIDIO_MIN_SCORE threshold.

    Returns an empty list if Presidio is unavailable or disabled.
    """
    if not _PRESIDIO_AVAILABLE or not settings.PRESIDIO_ENABLED:
        return []

    if not text or not text.strip():
        return []

    try:
        analyzer = _get_analyzer()
        results = analyzer.analyze(
            text=text,
            language="en",
            entities=PRESIDIO_ENTITIES,
            score_threshold=settings.PRESIDIO_MIN_SCORE,
        )
        findings: list[PresidioFinding] = []
        for r in results:
            findings.append(
                PresidioFinding(
                    type=r.entity_type,
                    value=text[r.start:r.end],
                    start=r.start,
                    end=r.end,
                    score=r.score,
                )
            )
        # Sort by start position
        findings.sort(key=lambda f: f.start)
        return findings

    except Exception as exc:  # pragma: no cover
        # PHI detection is fail-open: traffic continues, but this is an explicit
        # alarm event that SIEM/monitoring must alert on (phi.detection.failed).
        logger.error(
            "phi.detection.failed",
            fail_mode="fail_open",
            layer="presidio.analyze",
            error_class=type(exc).__name__,
            error=str(exc),
            msg="Presidio analysis failed; PHI detection degraded to empty findings",
        )
        return []


def anonymize_pii(
    text: str,
    operator: str | None = None,
) -> str:
    """
    Anonymize PII/PHI in text using Presidio AnonymizerEngine.

    Args:
        text:     Input text to anonymize.
        operator: Override the default operator from settings.
                  One of: "replace", "redact", "hash", "encrypt".

    Returns the anonymized text, or the original if Presidio is unavailable.
    """
    if not _PRESIDIO_AVAILABLE or not settings.PRESIDIO_ENABLED:
        return text

    if not text or not text.strip():
        return text

    op = operator or settings.PRESIDIO_ANONYMIZER_MODE

    try:
        analyzer = _get_analyzer()
        anonymizer = _get_anonymizer()

        analyzer_results = analyzer.analyze(
            text=text,
            language="en",
            entities=PRESIDIO_ENTITIES,
            score_threshold=settings.PRESIDIO_MIN_SCORE,
        )

        if not analyzer_results:
            return text

        # Build per-entity operator configuration
        operators: dict[str, Any] = {}
        for entity in PRESIDIO_ENTITIES:
            if op == "replace":
                operators[entity] = OperatorConfig("replace", {"new_value": f"[{entity}]"})
            elif op == "redact":
                operators[entity] = OperatorConfig("redact")
            elif op == "hash":
                operators[entity] = OperatorConfig("hash", {"hash_type": "sha256"})
            else:
                operators[entity] = OperatorConfig("replace", {"new_value": f"[{entity}]"})

        result = anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators,
        )
        return result.text

    except Exception as exc:  # pragma: no cover
        logger.warning(
            "presidio.anonymize.error",
            error=str(exc),
            msg="Presidio anonymization failed; returning original text",
        )
        return text
