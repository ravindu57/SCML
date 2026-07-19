"""
FastAPI application factory.

Registers all routers, configures OpenTelemetry, sets up lifecycle events,
and exposes health + metrics endpoints.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from trust_mediator.config import settings
from trust_mediator.api.dependencies import get_pipeline, get_policy_store
from trust_mediator.api.rate_limit import limiter
from trust_mediator.api.routers import audit, mediate, memory, policy
from trust_mediator.db.base import create_all_tables
from trust_mediator.logging_config import configure_logging

# Configure logging as early as possible so all subsequent loggers benefit.
configure_logging(env=settings.env)

logger = structlog.get_logger(__name__)

# ── Prometheus metrics ────────────────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "trustmediator_requests_total",
    "Total mediation requests",
    ["method", "endpoint", "decision"],
)
REQUEST_LATENCY = Histogram(
    "trustmediator_request_duration_seconds",
    "Request latency in seconds",
    ["endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.2, 0.4, 1.0, 2.0, 5.0],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup + shutdown lifecycle."""
    logger.info("trustmediator.starting", version="1.0.0", env=settings.env)

    # Create DB tables
    await create_all_tables()

    # Bootstrap default policy from YAML if DB is empty
    store = get_policy_store()
    await store.bootstrap_from_yaml()

    # Start pipeline background services (audit writer)
    pipeline = get_pipeline()
    await pipeline.start()

    logger.info("trustmediator.ready", port=settings.port)
    yield

    # Graceful shutdown
    await pipeline.stop()
    logger.info("trustmediator.stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="TrustMediator",
        description=(
            "Trust-Aware Context Mediation Middleware for Securing Agentic AI and RAG Systems. "
            "PRD v1.0 — all mediation decisions are logged with full provenance."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS (tighten in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.is_development else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Rate limiting ─────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # ── Middleware: request ID + structured logging ───────────────────────────
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        structlog.contextvars.bind_contextvars(request_id=request_id)
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        logger.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
        )
        REQUEST_LATENCY.labels(endpoint=request.url.path).observe(duration_ms / 1000)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-TrustMediator-Latency-Ms"] = f"{duration_ms:.1f}"
        structlog.contextvars.unbind_contextvars("request_id")
        return response

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(mediate.router)
    app.include_router(memory.router)
    app.include_router(audit.router)
    app.include_router(policy.router)

    # ── Health & metrics ──────────────────────────────────────────────────────
    @app.get("/health", tags=["system"], summary="Health check")
    async def health():
        return {
            "status": "ok",
            "service": "trust-mediator",
            "version": "1.0.0",
            "env": settings.env,
        }

    @app.get("/metrics", tags=["system"], summary="Prometheus metrics")
    async def metrics():
        from fastapi.responses import Response
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # ── Global error handler ──────────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("unhandled_exception", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal mediator error", "type": type(exc).__name__},
        )

    return app


app = create_app()


def main():
    uvicorn.run(
        "trust_mediator.api.app:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        reload=settings.is_development,
    )


if __name__ == "__main__":
    main()
