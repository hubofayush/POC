from app.core.phi.detector import detect_phi
from app.core.phi.masker import mask_phi

text = "Patient John Smith (SSN: 123-45-6789) emailed dr.jones@hospital.com. NPI: 1234567890. IP: 192.168.1.10"
print("=== detect_phi() findings ===")
findings = detect_phi(text)
for f in findings:
    print(f"  [{f.type}]  '{f.value}'  @{f.start}-{f.end}")

print()
print("=== mask_phi() output ===")
masked = mask_phi(text)
print(" ", masked)
