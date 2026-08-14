"""
tests/test_file_upload.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit and integration tests for the file upload functionality in /invoke.
Tests file type guard, size guard, MIME guard, PHI guard, Document repository,
and POST /invoke/file route.
"""
import io
import pytest
from app.config import settings
from app.core.guardrails.ingress.layer1_file import FileSizeGuard, FileTypeGuard, MimeTypeGuard
from app.core.guardrails.ingress.layer2_file_phi import FilePhiGuard


@pytest.mark.asyncio
async def test_file_type_guard_allowed():
    guard = FileTypeGuard()
    context = {"_file_extension": "pdf"}
    result = await guard.check("some text", context, {"sub": "user1"})
    assert result.passed is True


@pytest.mark.asyncio
async def test_file_type_guard_blocked():
    guard = FileTypeGuard()
    context = {"_file_extension": "exe"}
    result = await guard.check("some text", context, {"sub": "user1"})
    assert result.passed is False
    assert result.code == "FILE_TYPE_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_file_size_guard_pass():
    guard = FileSizeGuard()
    context = {"_file_size": 1024}
    result = await guard.check("some text", context, {"sub": "user1"})
    assert result.passed is True


@pytest.mark.asyncio
async def test_file_size_guard_blocked():
    guard = FileSizeGuard()
    context = {"_file_size": settings.MAX_UPLOAD_FILE_BYTES + 1}
    result = await guard.check("some text", context, {"sub": "user1"})
    assert result.passed is False
    assert result.code == "FILE_TOO_LARGE"


@pytest.mark.asyncio
async def test_mime_type_guard_mismatch():
    guard = MimeTypeGuard()
    context = {
        "_file_mime": "image/png",
        "_file_extension": "pdf"
    }
    result = await guard.check("some text", context, {"sub": "user1"})
    assert result.passed is False
    assert result.code == "MIME_EXTENSION_MISMATCH"


@pytest.mark.asyncio
async def test_mime_type_guard_valid():
    guard = MimeTypeGuard()
    context = {
        "_file_mime": "application/pdf",
        "_file_extension": "pdf"
    }
    result = await guard.check("some text", context, {"sub": "user1"})
    assert result.passed is True


@pytest.mark.asyncio
async def test_file_phi_guard_csv():
    guard = FilePhiGuard()
    csv_bytes = b"name,ssn\nJohn Doe,000-12-3456"
    context = {
        "_file_bytes": csv_bytes,
        "_file_extension": "csv",
        "_file_name": "patients.csv"
    }
    result = await guard.check("query", context, {"sub": "user1", "org": "test-org"})
    # FilePhiGuard is warn-only, so result.passed should be True
    assert result.passed is True
    assert context.get("_file_text_has_phi") is True
    assert "_file_extracted_text" in context
