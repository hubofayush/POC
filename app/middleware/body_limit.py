from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = request.headers.get("content-type", "").lower()
            is_multipart = "multipart/form-data" in content_type or request.url.path.endswith("/file")
            max_bytes = settings.MAX_UPLOAD_FILE_BYTES if is_multipart else settings.MAX_REQUEST_BODY_BYTES

            content_length = request.headers.get("content-length")
            try:
                if content_length is not None and int(content_length) > max_bytes:
                    return self._too_large(max_bytes)
            except ValueError:
                pass
            body = await request.body()
            if len(body) > max_bytes:
                return self._too_large(max_bytes)

            async def replay() -> dict:
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = replay
        return await call_next(request)

    def _too_large(self, limit: int | None = None) -> JSONResponse:
        max_limit = limit or settings.MAX_REQUEST_BODY_BYTES
        return JSONResponse(
            status_code=413,
            content={
                "title": "Request Entity Too Large",
                "status": 413,
                "detail": f"Request body exceeds the limit of {max_limit} bytes",
            },
        )

