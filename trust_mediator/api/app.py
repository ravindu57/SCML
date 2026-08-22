"""
FastAPI application factory.

Registers all routers, configures OpenTelemetry, sets up lifecycle events,
and exposes health + metrics endpoints.
"""

from __future__ import annotations

import ssl
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

from trust_mediator.config import require_secure_transport, settings
from trust_mediator.api.dependencies import get_pipeline, get_policy_store
from trust_mediator.api.rate_limit import limiter
from trust_mediator.api.routers import audit, mediate, memory, policy
from trust_mediator.db.base import create_all_tables
from trust_mediator.logging_config import configure_logging
from trust_mediator.observability import configure_observability, instrument_fastapi

# Configure logging as early as possible so all subsequent loggers benefit.
configure_logging(env=settings.env)

# NFR-OBS-01: install the tracer provider before any module builds its tracer.
# No-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set.
configure_observability()

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

    # Optional gRPC transport (FR-IG-02) — same pipeline, same policy
    grpc_server = None
    if settings.grpc_enabled:
        from trust_mediator.api.grpc.server import create_grpc_server

        grpc_server = await create_grpc_server(pipeline)
        await grpc_server.start()
        logger.info("trustmediator.grpc_ready", port=settings.grpc_port)

    logger.info("trustmediator.ready", port=settings.port)
    yield

    # Graceful shutdown
    if grpc_server is not None:
        await grpc_server.stop(grace=5)
    await pipeline.stop()
    logger.info("trustmediator.stopped")


def create_app() -> FastAPI:
    # NFR-SEC-03. Deliberately here and not in main(): the Dockerfile CMD and
    # the systemd unit both invoke `uvicorn trust_mediator.api.app:app`
    # directly, so a guard in main() would never run in the deployments that
    # need it. create_app is on every path.
    require_secure_transport("HTTP API")

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

    # CORS: open in dev for the local frontend; explicit allow-list in prod
    # (TRUST_MEDIATOR_CORS_ORIGINS). Empty prod list = no cross-origin access.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.is_development else settings.cors_origins,
        allow_credentials=not settings.is_development,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Host-header filtering (TRUST_MEDIATOR_TRUSTED_HOSTS); off when unset.
    if settings.trusted_hosts:
        from starlette.middleware.trustedhost import TrustedHostMiddleware

        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

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

    # ── Middleware: security response headers ─────────────────────────────────
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Cache-Control", "no-store"
        )  # mediation responses carry provenance/PII — never cache
        if settings.hsts_enabled:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response

    # ── Tracing (NFR-OBS-01) ──────────────────────────────────────────────────
    instrument_fastapi(app)

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


def _ssl_kwargs() -> dict[str, object]:
    """uvicorn TLS arguments (NFR-SEC-03), empty when TLS is not configured."""
    if not settings.tls_enabled:
        return {}
    kwargs: dict[str, object] = {
        "ssl_certfile": settings.tls_cert_file,
        "ssl_keyfile": settings.tls_key_file,
    }
    if settings.tls_ca_file:
        kwargs["ssl_ca_certs"] = settings.tls_ca_file
    if settings.tls_require_client_cert:
        # mTLS: present a CA and reject any peer that cannot chain to it.
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    return kwargs


def main():
    uvicorn.run(
        "trust_mediator.api.app:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        reload=settings.is_development,
        **_ssl_kwargs(),
    )


if __name__ == "__main__":
    main()
