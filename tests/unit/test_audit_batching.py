"""
Batched audit writes must preserve every guarantee of per-event writes
(FR-AL-01).

Batching exists because one transaction per event capped audit throughput at
~140 events/s, below what the request path sustains — so the queue grew
without bound and decisions were lost on shutdown. The speed-up is worthless
if it forks the hash chain, so these tests pin the integrity properties, not
the performance.

`test_audit_chain_multiworker` covers the single-event path; it writes via
`_write` directly and never exercises batching.
"""

from __future__ import annotations

import asyncio

import pytest

from trust_mediator.db.audit_repo import AuditRepository
from trust_mediator.db.base import create_all_tables
from trust_mediator.models.audit_event import AuditDecision, AuditModule
from trust_mediator.modules.audit_log.logger import AuditLogger


def _event(logger: AuditLogger, session_id: str, i: int):
    return logger.make_event(
        session_id=session_id,
        module=AuditModule.TOOL_POLICY,
        decision=AuditDecision.ALLOW,
        reason_code=f"step-{i}",
    )


@pytest.fixture(autouse=True)
async def _tables():
    await create_all_tables()


class TestBatchChainIntegrity:
    async def test_batch_produces_a_linear_verifiable_chain(self):
        logger = AuditLogger()
        session_id = "batch-linear"
        events = [_event(logger, session_id, i) for i in range(20)]

        await AuditRepository().append_chained_batch(events)

        replay = await logger.replay(session_id)
        assert replay.event_count == 20
        assert replay.chain_valid, replay.integrity_issues
        assert [e.seq_no for e in replay.events] == list(range(1, 21))

    async def test_batch_continues_an_existing_chain(self):
        """A batch must pick up from the stored tail, not restart at 1."""
        logger = AuditLogger()
        session_id = "batch-continues"

        await logger._write(_event(logger, session_id, 0))
        await AuditRepository().append_chained_batch(
            [_event(logger, session_id, i) for i in range(1, 6)]
        )

        replay = await logger.replay(session_id)
        assert replay.event_count == 6
        assert replay.chain_valid, replay.integrity_issues
        assert [e.seq_no for e in replay.events] == [1, 2, 3, 4, 5, 6]

    async def test_one_batch_spanning_sessions_chains_each_independently(self):
        """Sessions interleaved in a batch must not share a chain."""
        logger = AuditLogger()
        mixed = []
        for i in range(5):
            mixed.append(_event(logger, "batch-sess-a", i))
            mixed.append(_event(logger, "batch-sess-b", i))

        await AuditRepository().append_chained_batch(mixed)

        for session_id in ("batch-sess-a", "batch-sess-b"):
            replay = await logger.replay(session_id)
            assert replay.event_count == 5
            assert replay.chain_valid, replay.integrity_issues
            assert [e.seq_no for e in replay.events] == [1, 2, 3, 4, 5]

    async def test_empty_batch_is_a_noop(self):
        assert await AuditRepository().append_chained_batch([]) == []

    async def test_concurrent_workers_batching_one_session_stay_linear(self):
        """
        The guarantee that per-process chain state destroyed: two workers
        writing the same session concurrently must still produce one linear
        chain. The tail is re-read under a row lock inside every transaction,
        so batching must not weaken this.
        """
        worker_a, worker_b = AuditLogger(), AuditLogger()
        session_id = "batch-multiworker"

        await asyncio.gather(
            AuditRepository().append_chained_batch(
                [_event(worker_a, session_id, i) for i in range(8)]
            ),
            AuditRepository().append_chained_batch(
                [_event(worker_b, session_id, i) for i in range(8)]
            ),
        )

        replay = await worker_a.replay(session_id)
        assert replay.event_count == 16
        assert replay.chain_valid, replay.integrity_issues
        assert [e.seq_no for e in replay.events] == list(range(1, 17))


class TestWriterLoopBatching:
    async def test_queued_events_are_persisted_through_the_writer(self):
        logger = AuditLogger()
        session_id = "batch-writer-loop"
        await logger.start()
        try:
            for i in range(30):
                logger.log(_event(logger, session_id, i))
            await asyncio.wait_for(logger._queue.join(), timeout=20)
        finally:
            await logger.stop()

        replay = await logger.replay(session_id)
        assert replay.event_count == 30
        assert replay.chain_valid, replay.integrity_issues

    async def test_batch_max_of_one_still_works(self):
        """`AUDIT_BATCH_MAX=1` is the documented escape hatch to per-event writes."""
        logger = AuditLogger()
        logger._batch_max = 1
        session_id = "batch-max-one"
        await logger.start()
        try:
            for i in range(5):
                logger.log(_event(logger, session_id, i))
            await asyncio.wait_for(logger._queue.join(), timeout=20)
        finally:
            await logger.stop()

        replay = await logger.replay(session_id)
        assert replay.event_count == 5
        assert replay.chain_valid, replay.integrity_issues

    async def test_batch_failure_falls_back_to_per_event(self, monkeypatch):
        """
        One bad event must not discard the rest of the batch — FR-AL-01 wants
        every decision recorded, so a batch failure degrades to per-event
        writes rather than dropping the lot.
        """
        logger = AuditLogger()
        session_id = "batch-fallback"

        async def _boom(events, max_retries=5):
            raise RuntimeError("simulated batch failure")

        monkeypatch.setattr(logger._repo, "append_chained_batch", _boom)

        await logger._write_batch([_event(logger, session_id, i) for i in range(4)])

        replay = await logger.replay(session_id)
        assert replay.event_count == 4
        assert replay.chain_valid, replay.integrity_issues

    async def test_queue_join_completes_even_when_writes_fail(self, monkeypatch):
        """
        `stop()` awaits `queue.join()`. If a failing write skipped task_done()
        the service would hang on shutdown instead of draining.
        """
        logger = AuditLogger()

        async def _boom(events, max_retries=5):
            raise RuntimeError("simulated batch failure")

        async def _boom_single(event, max_retries=5):
            raise RuntimeError("simulated single failure")

        monkeypatch.setattr(logger._repo, "append_chained_batch", _boom)
        monkeypatch.setattr(logger._repo, "append_chained", _boom_single)

        await logger.start()
        try:
            for i in range(5):
                logger.log(_event(logger, "batch-join-hang", i))
            await asyncio.wait_for(logger._queue.join(), timeout=10)
        finally:
            await logger.stop()
