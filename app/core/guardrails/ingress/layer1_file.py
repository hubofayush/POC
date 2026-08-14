"""
app.core.guardrails.ingress.layer1_file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Layer 1 – File Structural Guards

Runs only when a file attachment is present in the /invoke request.
These are the cheapest file checks and run before any content parsing.

Guards:
  1. FileTypeGuard  – allow only pdf, csv, png, jpg/jpeg
  2. FileSizeGuard  – hard ceiling from settings.MAX_UPLOAD_FILE_BYTES
  3. MimeTypeGuard  – verify declared MIME matches allowed set (spoof prevention)
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

# Pre-computed sets from config strings (comma-separated)
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    e.strip().lower() for e in settings.ALLOWED_FILE_EXTENSIONS.split(",") if e.strip()
)
_ALLOWED_MIMES: frozenset[str] = frozenset(
    m.strip().lower() for m in settings.ALLOWED_MIME_TYPES.split(",") if m.strip()
)

# Extension → expected MIME prefix mapping for cross-check
_EXT_TO_MIME_PREFIX: dict[str, tuple[str, ...]] = {
    "pdf":   ("application/pdf",),
    "csv":   ("text/csv", "application/csv", "text/plain"),
    "png":   ("image/png",),
    "jpg":   ("image/jpeg",),
    "jpeg":  ("image/jpeg",),
}


# ---------------------------------------------------------------------------
# Context keys injected by the route handler for file guards to read
# ---------------------------------------------------------------------------
# context["_file_name"]       – original filename string
# context["_file_size"]       – int, raw byte length of the upload
# context["_file_mime"]       – declared MIME type from multipart headers
# context["_file_extension"]  – lower-case extension (without leading dot)
# ---------------------------------------------------------------------------


class FileTypeGuard(BaseGuardrail):
    """
    Rejects file uploads whose extension is not in the allowed set.

    Allowed (from config): pdf, csv, png, jpg, jpeg
    """
    name = "file_type"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        # Skip if no file in this request
        if "_file_extension" not in context:
            return PASS

        ext = context["_file_extension"].lower().lstrip(".")
        if ext not in _ALLOWED_EXTENSIONS:
            return GuardrailResult(
                passed=False,
                code="FILE_TYPE_NOT_ALLOWED",
                message=(
                    f"File type '.{ext}' is not permitted. "
                    f"Allowed types: {', '.join(sorted(_ALLOWED_EXTENSIONS))}."
                ),
                layer="ingress.layer1.file_type",
                details={
                    "submitted_extension": ext,
                    "allowed_extensions": sorted(_ALLOWED_EXTENSIONS),
                },
            )
        return PASS


class FileSizeGuard(BaseGuardrail):
    """
    Rejects files that exceed MAX_UPLOAD_FILE_BYTES (default 10 MB).
    """
    name = "file_size"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if "_file_size" not in context:
            return PASS

        size = int(context["_file_size"])
        max_bytes = settings.MAX_UPLOAD_FILE_BYTES
        if size > max_bytes:
            return GuardrailResult(
                passed=False,
                code="FILE_TOO_LARGE",
                message=(
                    f"Uploaded file is {size:,} bytes, exceeding the "
                    f"{max_bytes:,}-byte ({max_bytes // (1024*1024)} MB) limit."
                ),
                layer="ingress.layer1.file_size",
                details={"file_size_bytes": size, "max_bytes": max_bytes},
            )
        return PASS


class MimeTypeGuard(BaseGuardrail):
    """
    Verifies the declared Content-Type MIME is in the allowed set AND
    is consistent with the file extension (prevents extension spoofing).

    e.g. uploading a .exe renamed to .pdf with MIME application/pdf → blocked
         because the extension/MIME combination is internally consistent but
         the actual bytes check is out of scope for the POC.
    """
    name = "mime_type"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if "_file_mime" not in context or "_file_extension" not in context:
            return PASS

        mime = context["_file_mime"].lower().split(";")[0].strip()  # strip charset params
        ext  = context["_file_extension"].lower().lstrip(".")

        # 1. MIME must be in the global allowed set
        if mime not in _ALLOWED_MIMES:
            return GuardrailResult(
                passed=False,
                code="MIME_TYPE_NOT_ALLOWED",
                message=(
                    f"Content-Type '{mime}' is not permitted. "
                    f"Allowed MIME types: {', '.join(sorted(_ALLOWED_MIMES))}."
                ),
                layer="ingress.layer1.mime_type",
                details={"declared_mime": mime, "allowed_mimes": sorted(_ALLOWED_MIMES)},
            )

        # 2. Declared MIME must be consistent with the extension
        expected_prefixes = _EXT_TO_MIME_PREFIX.get(ext, ())
        if expected_prefixes and not any(mime.startswith(p) for p in expected_prefixes):
            return GuardrailResult(
                passed=False,
                code="MIME_EXTENSION_MISMATCH",
                message=(
                    f"Content-Type '{mime}' does not match the expected "
                    f"MIME for '.{ext}' files ({', '.join(expected_prefixes)})."
                ),
                layer="ingress.layer1.mime_type",
                details={
                    "declared_mime": mime,
                    "file_extension": ext,
                    "expected_mime_prefixes": list(expected_prefixes),
                },
            )
        return PASS
