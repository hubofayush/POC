from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

from app.config import settings
from app.middleware.error_handler import register_error_handlers
from app.middleware.rate_limit import add_rate_limiting, limiter
from app.models.database import create_tables, engine

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
add_rate_limiting(app)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "domain": "D5",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
from app.api.v1.auth import router as auth_router
from app.api.v1.audit import router as audit_router
from app.api.v1.traces import router as traces_router
from app.api.v1.invoke import router as invoke_router

app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(traces_router)
app.include_router(invoke_router)