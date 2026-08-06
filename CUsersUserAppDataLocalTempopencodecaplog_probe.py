import logging
import app.core.phi.detector as detector
import app.core.phi.presidio_engine as engine

def boom(text):
    raise RuntimeError("presidio down")
engine.analyze_pii = boom

records = []
handler = logging.Handler()
handler.setLevel(logging.ERROR)
handler.emit = lambda r: records.append(r)
root = logging.getLogger()
root.addHandler(handler)
root.setLevel(logging.ERROR)
try:
    findings = detector.detect_phi("Patient John Smith, SSN: 123-45-6789")
    print("findings:", [f.type for f in findings])
finally:
    root.removeHandler(handler)
print("captured:", len(records))
for r in records:
    print("msg:", repr(r.msg), "| level:", r.levelno)
    print("attrs:", r.fail_mode, r.layer, r.error_class)
