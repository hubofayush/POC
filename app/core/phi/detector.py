"""
app.core.phi.detector
~~~~~~~~~~~~~~~~~~~~~
Hybrid PHI & PII Detection Engine.

Detection Strategy (two-tier):
  Tier 1 – Regex patterns (fast, zero-latency, deterministic)
            Handles: SSN, credit card, NPI, DEA, MRN, license, email,
                     phone, IP address, zip code, dates, titled names.

  Tier 2 – Presidio NLP (spaCy en_core_web_lg + PatternRecognizers)
            Handles: free-text person names (no title prefix), locations,
                     organisations, contextual dates, and all structured
                     identifiers at higher accuracy.

Both tiers run and findings are merged via interval-span deduplication.
Tier 2 can be disabled via settings.PRESIDIO_ENABLED = False.

Includes interval span merging to resolve overlapping match collisions.
"""
import re
from dataclasses import dataclass

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_TITLE_PREFIX = r"(?i:Nurse|Patient|Dr|Doctor|Mr|Ms|Mrs|Prof|Clinician|Surgeon)\.?"
_STOP_WORDS = r"(?!(?:License|Licesens|RN|MD|DO|LPN|PA|Expired|Status|Check|Checking|Missing|Active|is|or|not|and|current|whether|about)\b)"

PHI_PATTERNS: dict[str, re.Pattern] = {
    # ── High Sensitivity Identifiers ──
    "ssn": re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "npi": re.compile(r"\b(?:NPI[:\s]*)?\b\d{10}\b", re.I),
    "dea": re.compile(r"\b(?:DEA[:\s]*)?[A-Z]{2}\d{7}\b", re.I),
    "medical_id": re.compile(r"\b(?:MRN|PID|PATIENT[- ]?ID)[:\s]*\d{5,}\b", re.I),
    "license": re.compile(r"\b(?:RN|MD|DO|LPN|PA)[-]?\d{5,}\b", re.I),

    # ── Contact & Location Identifiers ──
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\\s]?)?\(?\d{3}\)?[-.\\s]?\d{3}[-.\\s]?\d{4}\b"),
    "ip_address": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "zip": re.compile(r"\b\d{5}(?:-\d{4})?\b"),

    # ── Dates & Names ──
    "date": re.compile(
        r"\b(?:"
        r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"                     # MM/DD/YYYY or DD-MM-YY
        r"|\d{4}[/-]\d{1,2}[/-]\d{1,2}"                      # YYYY-MM-DD
        r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}" # March 12, 2026
        r")\b",
        re.I,
    ),
    "name": re.compile(
        r"\b(?:"
        # Title/Role prefix (Nurse, Dr., Patient, Mr., Ms., Mrs., Clinician, etc.) + 1-3 Name words
        rf"{_TITLE_PREFIX}\s+{_STOP_WORDS}[A-Za-z]+(?:['']s)?"
        rf"(?:\s+{_STOP_WORDS}[A-Za-z]+(?:['']s)?){{0,2}}"
        # Or capitalized Full Name (e.g. Sarah Thompson, Mary Doe)
        rf"|{_STOP_WORDS}[A-Z][a-z]+(?:\s+{_STOP_WORDS}[A-Z][a-z]+){{1,2}}(?:['']s)?"
        r")\b"
    ),
}


@dataclass
class PHIFinding:
    type: str
    value: str
    start: int
    end: int


def _merge_overlapping_findings(findings: list[PHIFinding]) -> list[PHIFinding]:
    """
    Sorts and merges overlapping PHI findings to guarantee that no two
    findings share character indices in the target text.
    """
    if not findings:
        return []

    # Sort by start index ascending, then by length descending
    sorted_findings = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[PHIFinding] = [sorted_findings[0]]

    for current in sorted_findings[1:]:
        prev = merged[-1]
        # If current finding overlaps with previous finding, resolve collision
        if current.start < prev.end:
            # Keep the longer span
            if (current.end - current.start) > (prev.end - prev.start):
                merged[-1] = current
        else:
            merged.append(current)

    return merged


def _regex_detect(text: str) -> list[PHIFinding]:
    """Run Tier 1 regex-based detection."""
    raw: list[PHIFinding] = []
    for phi_type, pattern in PHI_PATTERNS.items():
        for match in pattern.finditer(text):
            raw.append(
                PHIFinding(
                    type=phi_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return raw


def _presidio_detect(text: str) -> list[PHIFinding]:
    """Run Tier 2 Presidio NLP-based detection and convert to PHIFinding."""
    try:
        from app.core.phi.presidio_engine import analyze_pii  # lazy import
        presidio_findings = analyze_pii(text)
        return [
            PHIFinding(
                type=pf.type,
                value=pf.value,
                start=pf.start,
                end=pf.end,
            )
            for pf in presidio_findings
        ]
    except Exception as exc:
        # Fail-open: continue with regex-only results, but emit an explicit
        # alarm event so monitoring can alert that PHI detection degraded.
        logger.error(
            "phi.detection.failed",
            fail_mode="fail_open",
            layer="detector.tier2",
            error_class=type(exc).__name__,
            error=str(exc),
            msg="Presidio detection failed; falling back to regex only",
        )
        return []


def detect_phi(text: str, use_presidio: bool | None = None) -> list[PHIFinding]:
    """
    Scans text for all configured PHI/PII patterns and returns non-overlapping
    PHIFinding instances ordered by start position.

    Detection is two-tier:
      1. Regex patterns  — always runs (fast, deterministic, zero dependencies)
      2. Presidio NLP    — runs when settings.PRESIDIO_ENABLED is True (or
                           overridden via the use_presidio argument)

    Args:
        text:         Input text to scan.
        use_presidio: Override the settings.PRESIDIO_ENABLED flag for this call.
                      Useful in tests or for one-off calls.

    Returns:
        Merged, non-overlapping list of PHIFinding instances.
    """
    if not text:
        return []

    # Tier 1: Regex
    regex_findings = _regex_detect(text)

    # Tier 2: Presidio NLP
    run_presidio = use_presidio if use_presidio is not None else settings.PRESIDIO_ENABLED
    if run_presidio:
        presidio_findings = _presidio_detect(text)
        all_findings = regex_findings + presidio_findings
    else:
        all_findings = regex_findings

    return _merge_overlapping_findings(all_findings)