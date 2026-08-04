"""
NFR-OBS-01 — OpenTelemetry instrumentation.

The PRD requires structured logs, metrics and traces for every module.
Logs (structlog) and metrics (Prometheus `/metrics`) were already wired;
traces were declared in the dependencies and in config but never initialised,
so this requirement was unmet in practice.

Activation is opt-in and costs nothing when unused:

  - `OTEL_EXPORTER_OTLP_ENDPOINT` unset → no tracer provider is installed, the
    OpenTelemetry API hands back no-op tracers, and the `start_as_current_span`
    calls throughout the pipeline become near-free.
  - endpoint set → a real provider exports spans over OTLP.

Exporting requires the optional `[otlp]` extra:

    pip install -e ".[otlp]"

If the endpoint is configured but the exporter package is missing, that is
logged loudly and the service continues without tracing rather than failing
to start — observability must never take the data plane down (§8.3).

## Privacy

Span attributes carry decisions, labels, scores and identifiers — never
mediated content. Spans leave the process for a collector the mediator does
not control, so putting scanned text, memory contents or tool arguments in
them would turn the tracing pipeline into an exfiltration path for exactly the
data §6.6 exists to protect. Attribute helpers below enforce this by only
accepting scalar decision metadata.
"""

from __future__ import annotations

from typing import Any

import structlog
from opentelemetry import trace

from trust_mediator.config import settings

logger = structlog.get_logger(__name__)

_configured = False
_tracing_active = False

#: Span attribute namespace, so mediator spans are filterable in a collector
#: shared with the host application.
ATTR_MODULE = "trustmediator.module"
ATTR_DECISION = "trustmediator.decision"
ATTR_REASON = "trustmediator.reason_code"
ATTR_SESSION = "trustmediator.session_id"
ATTR_AGENT = "trustmediator.agent_id"
ATTR_TRUST_LABEL = "trustmediator.trust_label"
ATTR_SCORE = "trustmediator.score"


def configure_observability(span_exporter: Any = None, force: bool = False) -> bool:
    """
    Initialise tracing. Returns True when tracing is active.

    Args:
        span_exporter: Explicit exporter, used by tests to capture spans
            in memory without an OTLP collector.
        force: Re-configure even if already configured (tests only).
    """
    global _configured, _tracing_active
    if _configured and not force:
        return _tracing_active

    endpoint = settings.otel_exporter_otlp_endpoint
    if span_exporter is None and not endpoint:
        # Leave the API's no-op provider in place.
        logger.debug("observability.tracing_disabled", reason="no OTLP endpoint configured")
        _configured = True
        _tracing_active = False
        return False

    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

    if span_exporter is not None:
        processor = SimpleSpanProcessor(span_exporter)
    else:
        exporter = _build_otlp_exporter(endpoint)
        if exporter is None:
            _configured = True
            _tracing_active = False
            return False
        processor = BatchSpanProcessor(exporter)

    # TrustMediator is embedded middleware: the host application may already
    # own the global tracer provider. OpenTelemetry refuses to override it, so
    # attach to whatever is installed rather than clobbering the host's
    # configuration — mediation spans then land in the host's existing traces,
    # which is what an operator correlating an incident actually wants.
    current = trace.get_tracer_provider()
    if isinstance(current, TracerProvider):
        current.add_span_processor(processor)
        attached_to_existing = True
    else:
        provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": settings.otel_service_name,
                    "service.version": "1.0.0",
                    "deployment.environment": settings.env,
                }
            )
        )
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        attached_to_existing = False

    _configured = True
    _tracing_active = True
    logger.info(
        "observability.tracing_enabled",
        service=settings.otel_service_name,
        endpoint=endpoint or "in-memory",
        attached_to_existing_provider=attached_to_existing,
    )
    return True


def _build_otlp_exporter(endpoint: str):
    """Build an OTLP span exporter, or None when the extra is not installed."""
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError:
        logger.error(
            "observability.otlp_exporter_missing",
            endpoint=endpoint,
            hint='OTEL_EXPORTER_OTLP_ENDPOINT is set but the exporter is not '
            'installed; run: pip install -e ".[otlp]"',
        )
        return None
    return OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")


def instrument_fastapi(app: Any) -> None:
    """
    Instrument the HTTP surface. Health and metrics are excluded — they are
    polled continuously by Kubernetes and Prometheus and would otherwise
    dominate the trace volume without carrying mediation information.
    """
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        logger.warning("observability.fastapi_instrumentation_unavailable")
        return
    FastAPIInstrumentor.instrument_app(app, excluded_urls="health,metrics")


def get_tracer(name: str):
    """Tracer for a module. Returns a no-op tracer when tracing is disabled."""
    return trace.get_tracer(name)


def set_decision_attributes(
    span: Any,
    *,
    module: str,
    decision: str,
    reason_code: str = "",
    session_id: str = "",
    agent_id: str = "",
    trust_label: str = "",
    score: float | None = None,
) -> None:
    """
    Attach mediation decision metadata to a span.

    Only scalar decision metadata is accepted — never content. See the privacy
    note in the module docstring.
    """
    if not span.is_recording():
        return
    span.set_attribute(ATTR_MODULE, module)
    span.set_attribute(ATTR_DECISION, decision)
    if reason_code:
        span.set_attribute(ATTR_REASON, reason_code)
    if session_id:
        span.set_attribute(ATTR_SESSION, session_id)
    if agent_id:
        span.set_attribute(ATTR_AGENT, agent_id)
    if trust_label:
        span.set_attribute(ATTR_TRUST_LABEL, trust_label)
    if score is not None:
        span.set_attribute(ATTR_SCORE, float(score))


def reset_for_testing() -> None:
    """Allow a test to reconfigure tracing from scratch."""
    global _configured, _tracing_active
    _configured = False
    _tracing_active = False
