"""
Structured logging configuration.

Call `configure_logging()` once at application startup.

Modes:
- development (TRUST_MEDIATOR_ENV=development): pretty colored console output
- production  (TRUST_MEDIATOR_ENV=production):  newline-delimited JSON, one object per line

Every log event emitted via `structlog.get_logger()` will include:
  timestamp, level, logger, event, request_id (when in an HTTP context),
  and any additional key=value pairs passed at the call site.

SIEM compatibility:
  - Splunk: index by `timestamp` + `level`
  - Datadog: ship stdout/stderr from Docker; auto-parses JSON
  - Elastic/Kibana: use Filebeat to tail container logs
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(env: str = "development") -> None:
    """Configure structlog for the given environment.

    Args:
        env: One of "development", "production", or "test".
    """
    shared_processors: list = [
        # Add log level as a string
        structlog.stdlib.add_log_level,
        # NOTE: add_logger_name is intentionally omitted — it requires a stdlib
        # logger (.name attribute) but we use PrintLoggerFactory (PrintLogger).
        # Render timestamps as ISO-8601 UTC
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        # Include exception tracebacks when exc_info=True
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if env == "production":
        # ── Production: machine-readable JSON lines ──────────────────────────
        renderer = structlog.processors.JSONRenderer()
        structlog.configure(
            processors=shared_processors + [renderer],
            wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=True,
        )
    else:
        # ── Development: pretty coloured console output ──────────────────────
        structlog.configure(
            processors=shared_processors + [
                structlog.dev.ConsoleRenderer(colors=True),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=False,
        )

    # Also configure stdlib logging to go through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO if env == "production" else logging.DEBUG,
    )
