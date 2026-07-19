"""
Kafka forwarder for audit events (PRD §6.7 audit pipeline: durable queue
→ append-only storage → SIEM).

Optional: activates only when AUDIT_KAFKA_BOOTSTRAP is set. Uses aiokafka
if installed; otherwise logs one warning and no-ops so a missing optional
dependency can never break mediation (the DB write in AuditLogger remains
the authoritative record either way).

Delivery: acks="all" with idempotence for at-least-once delivery; keys are
session_id so per-session ordering is preserved within a partition.
"""

from __future__ import annotations

import structlog

from trust_mediator.models.audit_event import AuditEvent

logger = structlog.get_logger(__name__)

AUDIT_TOPIC = "trustmediator.audit"


class KafkaAuditForwarder:
    """Fire-and-forget publisher of finalized audit events to Kafka."""

    def __init__(self, bootstrap_servers: str, topic: str = AUDIT_TOPIC) -> None:
        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._producer = None
        self._disabled = False

    async def start(self) -> None:
        if not self._bootstrap:
            self._disabled = True
            return
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError:
            logger.warning(
                "kafka_forwarder.aiokafka_not_installed",
                hint="pip install 'trust-mediator[kafka]'",
            )
            self._disabled = True
            return
        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap,
                acks="all",
                enable_idempotence=True,
            )
            await self._producer.start()
            logger.info("kafka_forwarder.started", bootstrap=self._bootstrap, topic=self._topic)
        except Exception as e:
            logger.error("kafka_forwarder.start_failed", error=str(e))
            self._producer = None
            self._disabled = True

    async def stop(self) -> None:
        if self._producer is not None:
            try:
                await self._producer.stop()
            except Exception as e:
                logger.warning("kafka_forwarder.stop_error", error=str(e))
            self._producer = None

    @property
    def active(self) -> bool:
        return self._producer is not None

    async def forward(self, event: AuditEvent) -> None:
        """Publish one finalized event. Failures are logged, never raised —
        the DB hash chain is the authoritative record (FR-AL-01)."""
        if self._producer is None:
            return
        try:
            payload = event.model_dump_json().encode("utf-8")
            key = (event.session_id or "global").encode("utf-8")
            await self._producer.send_and_wait(self._topic, value=payload, key=key)
        except Exception as e:
            logger.warning("kafka_forwarder.send_failed", error=str(e), event_id=event.id)
