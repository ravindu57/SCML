"""Unit tests for the Kafka audit forwarder (FR-AL-03, PRD §6.7)."""

from __future__ import annotations

from unittest.mock import AsyncMock

from trust_mediator.models.audit_event import AuditDecision, AuditEvent, AuditModule
from trust_mediator.modules.audit_log.kafka_forwarder import KafkaAuditForwarder


def _event() -> AuditEvent:
    return AuditEvent(
        session_id="s1",
        module=AuditModule.INJECTION_SCANNER,
        decision=AuditDecision.ALLOW,
        reason_code="allow",
    )


class TestKafkaAuditForwarder:
    async def test_no_bootstrap_is_inactive_noop(self):
        fwd = KafkaAuditForwarder("")
        await fwd.start()
        assert fwd.active is False
        await fwd.forward(_event())  # must not raise
        await fwd.stop()

    async def test_unreachable_broker_disables_not_raises(self):
        """A dead broker must never break mediation (DB write is authoritative)."""
        fwd = KafkaAuditForwarder("127.0.0.1:1")
        await fwd.start()
        assert fwd.active is False
        await fwd.forward(_event())
        await fwd.stop()

    async def test_forward_publishes_keyed_by_session(self):
        fwd = KafkaAuditForwarder("fake:9092")
        producer = AsyncMock()
        fwd._producer = producer
        await fwd.forward(_event())
        producer.send_and_wait.assert_awaited_once()
        args, kwargs = producer.send_and_wait.call_args
        assert args[0] == "trustmediator.audit"
        assert kwargs["key"] == b"s1"

    async def test_send_failure_is_swallowed(self):
        fwd = KafkaAuditForwarder("fake:9092")
        producer = AsyncMock()
        producer.send_and_wait.side_effect = RuntimeError("broker gone")
        fwd._producer = producer
        await fwd.forward(_event())  # must not raise
