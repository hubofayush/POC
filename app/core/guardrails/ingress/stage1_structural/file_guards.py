"""
stage1_structural.file_guards
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
File type, size, and MIME validation guards (no-op when no file is present).
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.guardrails.base import PASS, BaseGuardrail, GuardrailResult

_ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    e.strip().lower() for e in settings.ALLOWED_FILE_EXTENSIONS.split(",") if e.strip()
)
_ALLOWED_MIMES: frozenset[str] = frozenset(
    m.strip().lower() for m in settings.ALLOWED_MIME_TYPES.split(",") if m.strip()
)
_EXT_TO_MIME_PREFIX: dict[str, tuple[str, ...]] = {
    "pdf":   ("application/pdf",),
    "csv":   ("text/csv", "application/csv", "text/plain"),
    "png":   ("image/png",),
    "jpg":   ("image/jpeg",),
    "jpeg":  ("image/jpeg",),
}


class FileTypeGuard(BaseGuardrail):
    name = "file_type"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if "_file_extension" not in context:
            return PASS
        ext = context["_file_extension"].lower().lstrip(".")
        if ext not in _ALLOWED_EXTENSIONS:
            return GuardrailResult(
                passed=False,
                code="FILE_TYPE_NOT_ALLOWED",
                message=f"File type '.{ext}' is not permitted. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}.",
                layer="ingress.stage1.file_type",
                details={"submitted_extension": ext, "allowed_extensions": sorted(_ALLOWED_EXTENSIONS)},
            )
        return PASS


class FileSizeGuard(BaseGuardrail):
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
                message=f"File is {size:,} bytes, exceeding the {max_bytes:,}-byte limit.",
                layer="ingress.stage1.file_size",
                details={"file_size_bytes": size, "max_bytes": max_bytes},
            )
        return PASS


class MimeTypeGuard(BaseGuardrail):
    name = "mime_type"

    async def check(
        self, input_text: str, context: dict[str, Any], user: dict[str, Any]
    ) -> GuardrailResult:
        if "_file_mime" not in context or "_file_extension" not in context:
            return PASS
        mime = context["_file_mime"].lower().split(";")[0].strip()
        ext  = context["_file_extension"].lower().lstrip(".")
        if mime not in _ALLOWED_MIMES:
            return GuardrailResult(
                passed=False,
                code="MIME_TYPE_NOT_ALLOWED",
                message=f"Content-Type '{mime}' is not permitted.",
                layer="ingress.stage1.mime_type",
                details={"declared_mime": mime, "allowed_mimes": sorted(_ALLOWED_MIMES)},
            )
        expected_prefixes = _EXT_TO_MIME_PREFIX.get(ext, ())
        if expected_prefixes and not any(mime.startswith(p) for p in expected_prefixes):
            return GuardrailResult(
                passed=False,
                code="MIME_EXTENSION_MISMATCH",
                message=f"Content-Type '{mime}' does not match expected MIME for '.{ext}' files.",
                layer="ingress.stage1.mime_type",
                details={"declared_mime": mime, "file_extension": ext, "expected_mime_prefixes": list(expected_prefixes)},
            )
        return PASS
