"""
tests/test_phi.py
~~~~~~~~~~~~~~~~~~
Comprehensive unit tests for the Production HIPAA 18 PHI/PII Detection and Masking engine.
"""
import pytest
from app.core.phi.detector import detect_phi
from app.core.phi.masker import mask_phi, smart_mask


def test_detect_ssn():
    findings = detect_phi("SSN: 123-45-6789")
    assert len(findings) == 1
    assert findings[0].type == "ssn"


def test_detect_email():
    findings = detect_phi("Contact: john@clinic.org")
    assert len(findings) == 1
    assert findings[0].type == "email"


def test_detect_npi():
    findings = detect_phi("Provider NPI 1234567890 active.")
    types = [f.type for f in findings]
    assert "npi" in types


def test_detect_dea():
    findings = detect_phi("Prescriber DEA AB1234567 registered.")
    types = [f.type for f in findings]
    assert "dea" in types


def test_detect_credit_card():
    findings = detect_phi("Card: 4532-0123-4567-8901")
    types = [f.type for f in findings]
    assert "credit_card" in types


def test_detect_ip_address():
    findings = detect_phi("Source IP: 192.168.1.100")
    types = [f.type for f in findings]
    assert "ip_address" in types


def test_detect_multiple():
    text = "Patient John Smith, SSN: 123-45-6789, DOB: 05/15/1985"
    findings = detect_phi(text)
    types = {f.type for f in findings}
    assert "ssn" in types
    assert "date" in types
    assert "name" in types


def test_no_phi():
    findings = detect_phi("All credentials verified. Status: ACTIVE.")
    assert len(findings) == 0


def test_detect_nurse_name():
    findings = detect_phi("Check whether nurse Johnsons Licesens is expired or not?")
    types = [f.type for f in findings]
    assert "name" in types
    assert findings[0].value.lower() == "nurse johnsons"


def test_mask_ssn():
    assert smart_mask("123-45-6789", "ssn") == "***-**-6789"


def test_mask_email():
    assert smart_mask("john@clinic.org", "email") == "j***@clinic.org"


def test_mask_phone():
    assert smart_mask("555-123-4567", "phone") == "***-***-4567"


def test_mask_license():
    result = smart_mask("RN-987654", "license")
    assert "RN" in result
    assert "987654" not in result


def test_mask_npi():
    assert smart_mask("1234567890", "npi") == "NPI-******7890"


def test_mask_dea():
    assert smart_mask("AB1234567", "dea") == "AB*****67"


def test_mask_credit_card():
    assert smart_mask("4532-0123-4567-8901", "credit_card") == "****-****-****-8901"


def test_role_aware_masking_hr_masks():
    text = "Patient John Smith, SSN: 123-45-6789, email: john@clinic.org"
    masked = mask_phi(text, role="hr")
    assert "123-45-6789" not in masked
    assert "john@clinic.org" not in masked
    assert "***-**-6789" in masked


def test_role_aware_masking_admin_bypasses():
    text = "Patient John Smith, SSN: 123-45-6789, email: john@clinic.org"
    # Admin role is authorized for PHI; retains original text
    unmasked = mask_phi(text, role="admin")
    assert unmasked == text


def test_clean_text_unchanged():
    text = "Compliance status: ACTIVE. All good."
    assert mask_phi(text) == text


def test_presidio_failure_emits_alarm_and_fails_open(caplog, monkeypatch):
    import logging
    import re
    import app.core.phi.presidio_engine as engine
    from app.core.phi.masker import mask_phi

    ansi = re.compile(r"\x1b\[[0-9;]*m")

    def boom(text):
        raise RuntimeError("presidio down")

    monkeypatch.setattr(engine, "analyze_pii", boom)

    with caplog.at_level(logging.ERROR):
        findings = detect_phi("Patient John Smith, SSN: 123-45-6789")
        assert isinstance(findings, list)
        assert any(f.type == "ssn" for f in findings)
        assert isinstance(mask_phi("Compliance for Marcus Webb", role="hr"), str)

    alarm_events = [r for r in caplog.records if "phi.detection.failed" in r.getMessage()]
    assert alarm_events, "expected phi.detection.failed alarm event"
    text = ansi.sub("", alarm_events[0].getMessage())
    assert "fail_mode=fail_open" in text
    assert "layer=detector.tier2" in text
    assert "error_class=RuntimeError" in text


def test_presidio_analyze_failure_emits_alarm(caplog, monkeypatch):
    import logging
    import re
    import app.core.phi.presidio_engine as engine

    ansi = re.compile(r"\x1b\[[0-9;]*m")

    monkeypatch.setattr(engine, "_PRESIDIO_AVAILABLE", True)

    def boom():
        raise RuntimeError("nlp model missing")

    monkeypatch.setattr(engine, "_get_analyzer", boom)

    with caplog.at_level(logging.ERROR):
        findings = engine.analyze_pii("John Smith 123-45-6789")
        assert findings == []

    alarm_events = [r for r in caplog.records if "phi.detection.failed" in r.getMessage()]
    assert alarm_events
    text = ansi.sub("", alarm_events[0].getMessage())
    assert "layer=presidio.analyze" in text
    assert "fail_mode=fail_open" in text