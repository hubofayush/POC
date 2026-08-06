import re


def verify_citations(output: str, citations: list[str]) -> list[str]:
    return citations


def filter_by_role(output: str, user_role: str) -> str:
    if user_role in ("hr", "clinician"):
        sensitive = ["diagnosis", "treatment", "prescription", "medication"]
        for word in sensitive:
            output = re.sub(rf"\b{word}\b", "[REDACTED]", output, flags=re.IGNORECASE)
    return output
