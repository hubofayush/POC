from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import generate_latest
from sqlalchemy import text

from app.config import settings
from app.middleware.error_handler import register_error_handlers
from app.middleware.rate_limit import add_rate_limiting
from app.middleware.body_limit import BodySizeLimitMiddleware
from app.middleware.http_metrics import HttpMetricsMiddleware
from app.models.database import create_tables, engine
from app.core.logging import get_logger

logger = get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.DB_AUTO_CREATE:
        await create_tables()
    yield
    await engine.dispose()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)

# CORS: explicit allowlist only (credentials require exact origins, never "*")
_cors_origins = [o.strip() for o in settings.CORS_ALLOW_ORIGINS.split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

register_error_handlers(app)
app.add_middleware(BodySizeLimitMiddleware)
add_rate_limiting(app)
app.add_middleware(HttpMetricsMiddleware)  # outermost: captures all paths/statuses


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "domain": "D5",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health/live")
async def health_live():
    return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/health/ready")
async def health_ready():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("health.ready_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint():
    return Response(
        content=generate_latest(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
    
from app.api.v1.auth import router as auth_router
from app.api.v1.audit import router as audit_router
from app.api.v1.traces import router as traces_router
from app.api.v1.invoke import router as invoke_router

app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(traces_router)
app.include_router(invoke_router)