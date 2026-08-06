from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            try:
                if content_length is not None and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                    return self._too_large()
            except ValueError:
                pass
            body = await request.body()
            if len(body) > settings.MAX_REQUEST_BODY_BYTES:
                return self._too_large()

            async def replay() -> dict:
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = replay
        return await call_next(request)

    def _too_large(self) -> JSONResponse:
        return JSONResponse(
            status_code=413,
            content={
                "title": "Request Entity Too Large",
                "status": 413,
                "detail": f"Request body exceeds the limit of {settings.MAX_REQUEST_BODY_BYTES} bytes",
            },
        )
