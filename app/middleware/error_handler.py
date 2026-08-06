from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import structlog

from app.core.guardrails.base import GuardrailException

logger = structlog.get_logger(__name__)

# HTTP status codes to use per guardrail code prefix
_CONSENT_CODES = frozenset(["CONSENT_DENIED", "PHI_ACCESS_DENIED"])

def register_error_handlers(app: FastAPI):
    @app.exception_handler(StarletteHTTPException)
    async def http_exc_handler(request: Request, exc: StarletteHTTPException):
        logger.warning("http_error", status=exc.status_code, detail=exc.detail, path=str(request.url))
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": "https://tools.ietf.org/html/rfc9457",
                "title": exc.detail,
                "status": exc.status_code,
                "detail": exc.detail,
                "instance": str(request.url),
            },
        )

    @app.exception_handler(GuardrailException)
    async def guardrail_exc_handler(request: Request, exc: GuardrailException):
        result = exc.result
        http_status = 403 if result.code in _CONSENT_CODES else 422
        logger.warning(
            "guardrail.blocked",
            code=result.code,
            layer=result.layer,
            message=result.message,
            trace_id=exc.trace_id,
            path=str(request.url),
            status=http_status,
        )
        return JSONResponse(
            status_code=http_status,
            content={
                "type": "https://tools.ietf.org/html/rfc9457",
                "title": "Request Blocked by Guardrail",
                "status": http_status,
                "detail": result.message,
                "instance": str(request.url),
                "extensions": {
                    "guardrail": result.name if hasattr(result, "name") else result.layer.split(".")[-1],
                    "code": result.code,
                    "layer": result.layer,
                    "trace_id": exc.trace_id,
                    "details": result.details,
                },
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exc_handler(request: Request, exc: Exception):
        logger.exception("unhandled_error", path=str(request.url), error=str(exc))
        return JSONResponse(
            status_code=500,
            content={
                "type": "https://tools.ietf.org/html/rfc9457",
                "title": "Internal Server Error",
                "status": 500,
                "detail": "An unexpected error occurred",
            },
        )