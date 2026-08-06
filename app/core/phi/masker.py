"""
app.core.phi.masker
~~~~~~~~~~~~~~~~~~~
Hybrid PHI & PII Masking Engine.

Applies smart redaction rules per PHI type (SSN, Email, Phone, NPI, DEA, etc.),
including all Presidio NLP entity types (PERSON, LOCATION, DATE_TIME, etc.),
with defensive parsing against IndexError/ValueError crashes and role-aware
policy checks.
"""
from __future__ import annotations

import re
from .detector import detect_phi


def smart_mask(value: str, phi_type: str) -> str:
    """
    Applies type-specific smart masking rules to sensitive values.
    Handles both regex-detected types and Presidio NLP entity types.
    Includes defensive checks against malformed or partial values.
    """
    if not value:
        return ""

    # ── Regex-detected types (Tier 1) ──────────────────────────────────────

    if phi_type == "ssn":
        cleaned = re.sub(r"\D", "", value)
        return f"***-**-{cleaned[-4:]}" if len(cleaned) >= 4 else "***-**-****"

    elif phi_type == "email":
        if "@" in value:
            parts = value.split("@", 1)
            local = parts[0]
            domain = parts[1] if len(parts) > 1 else "domain.com"
            local_masked = f"{local[0]}***" if local else "***"
            return f"{local_masked}@{domain}"
        return "***@***.com"

    elif phi_type == "phone":
        digits = re.sub(r"\D", "", value)
        return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***-***-****"

    elif phi_type == "license" or phi_type == "PROVIDER_LICENSE":
        prefix_match = re.match(r"^[A-Z]+", value, re.I)
        prefix = prefix_match.group().upper() if prefix_match else "LIC"
        return f"{prefix}-*****"

    elif phi_type == "npi" or phi_type == "NPI":
        return f"NPI-******{value[-4:]}" if len(value) >= 4 else "NPI-**********"

    elif phi_type == "dea" or phi_type == "DEA_NUMBER":
        prefix = value[:2].upper() if len(value) >= 2 else "DEA"
        return f"{prefix}*****{value[-2:]}" if len(value) >= 4 else "DEA*******"

    elif phi_type == "credit_card" or phi_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****-****-****-****"

    elif phi_type == "ip_address" or phi_type == "IP_ADDRESS":
        return "127.0.0.1"

    elif phi_type == "medical_id" or phi_type == "MEDICAL_RECORD_NUMBER":
        return "MRN-*****"

    elif phi_type == "zip":
        return "*****"

    elif phi_type == "date" or phi_type == "DATE_TIME":
        return "**/**/****"

    elif phi_type == "name":
        # Regex name: mask each word to first-letter + stars
        parts = value.split()
        return " ".join(f"{p[0]}***" if p else "***" for p in parts)

    # ── Presidio NLP entity types (Tier 2) ─────────────────────────────────

    elif phi_type == "PERSON":
        # NER-detected free-text name: mask each word individually
        parts = value.split()
        masked_parts = []
        for p in parts:
            # Preserve title prefixes (Dr., Mr., Ms., etc.) unmasked
            if re.match(r"^(?:Dr|Mr|Mrs|Ms|Prof|Nurse|Patient)\.?$", p, re.I):
                masked_parts.append(p)
            else:
                masked_parts.append(f"{p[0]}***" if len(p) > 0 else "***")
        return " ".join(masked_parts)

    elif phi_type == "LOCATION":
        return "[LOCATION]"

    elif phi_type == "EMAIL_ADDRESS":
        # Same as email
        if "@" in value:
            parts = value.split("@", 1)
            local = parts[0]
            domain = parts[1] if len(parts) > 1 else "domain.com"
            local_masked = f"{local[0]}***" if local else "***"
            return f"{local_masked}@{domain}"
        return "***@***.com"

    elif phi_type == "PHONE_NUMBER":
        digits = re.sub(r"\D", "", value)
        return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***-***-****"

    elif phi_type == "US_SSN":
        cleaned = re.sub(r"\D", "", value)
        return f"***-**-{cleaned[-4:]}" if len(cleaned) >= 4 else "***-**-****"

    elif phi_type == "URL":
        return "[URL]"

    elif phi_type == "US_PASSPORT":
        return "[PASSPORT]"

    elif phi_type == "US_DRIVER_LICENSE":
        return "[DL-*****]"

    elif phi_type == "MEDICAL_LICENSE":
        return "[MED-LICENSE]"

    elif phi_type == "IBAN_CODE":
        return "[IBAN]"

    else:
        # Fallback: full redaction
        return "*" * max(len(value), 4)


def mask_phi(
    text: str,
    role: str = "hr",
    bypass_roles: tuple[str, ...] = ("admin", "compliance_officer"),
) -> str:
    """
    Redacts or smartly masks PHI/PII findings in text based on caller role.

    Uses the hybrid detector (Tier 1 regex + Tier 2 Presidio NLP) to find
    all PHI entities, then applies type-specific smart masking.

    - Roles in `bypass_roles` (admin, compliance_officer) retain original text.
    - Standard roles (hr, clinician) receive sanitized output with smart masks.
    """
    if not text:
        return text

    # Role-based policy check: privileged roles authorized for PHI bypass masking
    if role in bypass_roles:
        return text

    findings = detect_phi(text)
    if not findings:
        return text

    # Reconstruct text in reverse position order to preserve character offsets
    masked = list(text)
    for f in sorted(findings, key=lambda x: -x.start):
        replacement = smart_mask(f.value, f.type)
        masked[f.start:f.end] = replacement

    return "".join(masked)