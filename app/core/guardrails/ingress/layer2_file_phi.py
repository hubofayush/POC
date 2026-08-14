"""
app.core.guardrails.ingress.layer2_file_phi
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 2 – File PHI / Content Guard

Runs only when a file is present AND the file is text-extractable
(CSV or PDF).  PNG/JPG screenshots are passed through — D3's vision
model handles OCR and any PHI in the image never enters D5 as plain text.

Guard:
  FilePhiGuard – extract text from CSV/PDF, then reuse the existing
                 PHIInInputGuard logic to detect/warn about PHI content.
"""
from __future__ import annotations

import io
from typing import Any

from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Lightweight text extractors (no heavy deps beyond stdlib + optional PyPDF2)
# ---------------------------------------------------------------------------

def _extract_csv_text(raw: bytes) -> str:
    """Decode CSV bytes as UTF-8 (with fallback to latin-1) and return text."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _extract_pdf_text(raw: bytes) -> str:
    """
    Extract text from PDF bytes.

    Uses pypdf if installed (lightweight pure-Python PDF reader).
    Falls back gracefully to an empty string when the library is absent so
    the guard becomes pass-through rather than crashing the pipeline.
    """
    try:
        import pypdf  # optional dependency

        reader = pypdf.PdfReader(io.BytesIO(raw))
        pages: list[str] = []
        for page in reader.pages:
            text = page.extract_text() or ""
            pages.append(text)
        return "\n".join(pages)
    except ImportError:
        logger.warning(
            "file_phi_guard.pypdf_missing",
            msg="pypdf not installed; PDF text extraction skipped. "
                "Install pypdf to enable PHI scanning on PDF uploads.",
        )
        return ""
    except Exception as exc:
        logger.warning(
            "file_phi_guard.pdf_extract_failed",
            error=str(exc),
            msg="PDF text extraction failed; PHI scan skipped for this file.",
        )
        return ""


class FilePhiGuard(BaseGuardrail):
    """
    Extracts text from CSV/PDF uploads and runs the existing PHI detector
    on the extracted content.

    Behaviour:
    - CSV/PDF: extract text → scan with detect_phi()
    - PNG/JPG: skip (image bytes; PHI detected by D3 vision model)
    - No file in request: skip (pass-through)

    This guard is WARN-ONLY (always passes) — consistent with PHIInInputGuard.
    It logs a structured warning so the compliance team can audit file uploads
    that contained PHI before the file was forwarded to D3/D1.
    """
    name = "file_phi"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        raw: bytes | None = context.get("_file_bytes")
        ext: str = context.get("_file_extension", "").lower().lstrip(".")

        # Only text-extractable formats
        if raw is None or ext not in ("csv", "pdf"):
            return PASS

        # Extract text based on file type
        if ext == "csv":
            file_text = _extract_csv_text(raw)
        else:  # pdf
            file_text = _extract_pdf_text(raw)

        if not file_text.strip():
            return PASS

        # Reuse the existing PHI detector (regex + optional Presidio)
        try:
            from app.core.phi.detector import detect_phi
            findings = detect_phi(file_text)
        except Exception as exc:
            logger.warning(
                "file_phi_guard.detection_failed",
                error=str(exc),
                msg="PHI detection on file content failed; skipping.",
            )
            return PASS

        if findings:
            phi_types = list({f.type for f in findings})
            logger.warning(
                "file_phi_guard.phi_detected_in_upload",
                filename=context.get("_file_name", "unknown"),
                file_type=ext,
                phi_types=phi_types,
                finding_count=len(findings),
                user_id=user.get("sub"),
                org=user.get("org"),
                trace_id=context.get("_trace_id", ""),
                msg=(
                    f"PHI detected in uploaded {ext.upper()} file. "
                    "Content will be masked before forwarding to D3."
                ),
            )
            # Store a flag so invoke.py knows to mask the extracted text
            context["_file_text_has_phi"] = True
            context["_file_phi_types"] = phi_types

        # Store the extracted text for invoke.py to forward to D3
        context["_file_extracted_text"] = file_text

        # Always PASS — PHI in uploaded files is warn-only (same as PHIInInputGuard)
        return PASS
