"""
Bounded audit queue and overflow accounting (FR-AL-01, NFR-PERF-04).

The queue used to be unbounded. Offered load above writer throughput grew it
in memory until the process died, taking every queued decision with it — and
nothing recorded that the loss had happened.

Bounding it does not make the loss acceptable; it makes it *visible*. These
tests pin three properties:

  1. Enqueue never blocks the request path, even when saturated.
  2. Drops are counted and the join() accounting stays balanced, so shutdown
     still drains instead of hanging.
  3. The gap is written into the affected session's own hash chain, so a
     forensic replay shows exactly how much was lost and where.
"""

from __future__ import annotations

import asyncio

import pytest

from trust_mediator.db.base import create_all_tables
from trust_mediator.models.audit_event import AuditDecision, AuditModule
from trust_mediator.modules.audit_log.logger import AuditLogger


@pytest.fixture(autouse=True)
async def _tables():
    await create_all_tables()


def _logger(maxsize: int, policy: str = "drop_newest") -> AuditLogger:
    """An AuditLogger with a deliberately tiny queue."""
    lg = AuditLogger()
    lg._queue = asyncio.Queue(maxsize=maxsize)
    lg._overflow_policy = policy
    return lg


def _event(lg: AuditLogger, session_id: str, i: int):
    return lg.make_event(
        session_id=session_id,
        module=AuditModule.TOOL_POLICY,
        decision=AuditDecision.ALLOW,
        reason_code=f"step-{i}",
    )


class TestBounding:
    def test_queue_respects_configured_maxsize(self):
        lg = _logger(maxsize=3)
        for i in range(10):
            lg.log(_event(lg, "s", i))
        assert lg._queue.qsize() == 3

    def test_enqueue_never_blocks_when_full(self):
        """NFR-PERF-04 — audit must never apply back-pressure to a request."""
        lg = _logger(maxsize=1)
        for i in range(200):
            lg.log(_event(lg, "s", i))  # would hang if this awaited space
        assert lg.dropped_total == 199

    def test_unbounded_when_maxsize_is_zero(self):
        lg = _logger(maxsize=0)
        for i in range(500):
            lg.log(_event(lg, "s", i))
        assert lg._queue.qsize() == 500
        assert lg.dropped_total == 0


class TestOverflowPolicies:
    def test_drop_newest_keeps_the_existing_backlog(self):
        lg = _logger(maxsize=2, policy="drop_newest")
        for i in range(5):
            lg.log(_event(lg, "s", i))
        kept = [lg._queue.get_nowait().reason_code for _ in range(2)]
        assert kept == ["step-0", "step-1"]
        assert lg.dropped_total == 3

    def test_drop_oldest_prefers_recent_events(self):
        """Under an attack-driven flood the newest events are the interesting ones."""
        lg = _logger(maxsize=2, policy="drop_oldest")
        for i in range(5):
            lg.log(_event(lg, "s", i))
        kept = [lg._queue.get_nowait().reason_code for _ in range(2)]
        assert kept == ["step-3", "step-4"]
        assert lg.dropped_total == 3

    async def test_drop_oldest_keeps_join_accounting_balanced(self):
        """
        Eviction calls get_nowait(); without a matching task_done() the
        unfinished-task counter drifts upward and join() never returns, so
        shutdown hangs instead of draining.
        """
        lg = _logger(maxsize=2, policy="drop_oldest")
        for i in range(6):
            lg.log(_event(lg, "s", i))   # 4 evictions

        while not lg._queue.empty():
            lg._queue.get_nowait()
            lg._queue.task_done()

        # Hangs here if any eviction skipped its task_done().
        await asyncio.wait_for(lg._queue.join(), timeout=5)

    async def test_stop_still_drains_after_overflow(self):
        lg = _logger(maxsize=2, policy="drop_oldest")
        await lg.start()
        try:
            for i in range(50):
                lg.log(_event(lg, "drain-after-overflow", i))
            await asyncio.wait_for(lg._queue.join(), timeout=20)
        finally:
            await asyncio.wait_for(lg.stop(), timeout=20)


class TestDropAccounting:
    def test_drops_are_tracked_per_session(self):
        lg = _logger(maxsize=1)
        lg.log(_event(lg, "sess-a", 0))       # fills the queue
        lg.log(_event(lg, "sess-a", 1))       # dropped
        lg.log(_event(lg, "sess-b", 0))       # dropped
        lg.log(_event(lg, "sess-b", 1))       # dropped
        assert lg._dropped == {"sess-a": 1, "sess-b": 2}
        assert lg.dropped_total == 3


class TestGapMarker:
    """The loss must land in the chain, not only in a log line."""

    async def test_marker_is_written_into_the_affected_session(self):
        lg = _logger(maxsize=1)
        session = "gap-marker-session"
        lg.log(_event(lg, session, 0))
        for i in range(1, 8):
            lg.log(_event(lg, session, i))    # 7 dropped
        assert lg.dropped_total == 7

        # Drain the one queued event, then flush markers as the writer would.
        queued = lg._queue.get_nowait()
        lg._queue.task_done()
        await lg._write_batch([queued])
        await lg._flush_gap_markers()

        replay = await lg.replay(session)
        gaps = [e for e in replay.events if e.reason_code == "audit_gap"]
        assert len(gaps) == 1
        assert gaps[0].details["dropped_events"] == 7
        assert gaps[0].module == AuditModule.SYSTEM

    async def test_chain_stays_verifiable_across_a_gap(self):
        """
        A gap is a hole in the *record*, not a break in the chain. Replay must
        still verify, or an operator cannot distinguish overload from tampering.
        """
        lg = _logger(maxsize=1)
        session = "gap-chain-valid"
        lg.log(_event(lg, session, 0))
        for i in range(1, 5):
            lg.log(_event(lg, session, i))

        queued = lg._queue.get_nowait()
        lg._queue.task_done()
        await lg._write_batch([queued])
        await lg._flush_gap_markers()

        replay = await lg.replay(session)
        assert replay.chain_valid, replay.integrity_issues

    async def test_counters_reset_after_flush(self):
        lg = _logger(maxsize=1)
        lg.log(_event(lg, "gap-reset", 0))
        lg.log(_event(lg, "gap-reset", 1))
        await lg._flush_gap_markers()
        assert lg._dropped == {}
        # Lifetime total is deliberately not reset — it is a metric.
        assert lg.dropped_total == 1

    async def test_failed_marker_write_is_retried_not_lost(self, monkeypatch):
        """Losing the record of a loss is the one unacceptable outcome."""
        lg = _logger(maxsize=1)
        lg.log(_event(lg, "gap-retry", 0))
        lg.log(_event(lg, "gap-retry", 1))

        async def _boom(event, max_retries=5):
            raise RuntimeError("db down")

        monkeypatch.setattr(lg._repo, "append_chained", _boom)
        await lg._flush_gap_markers()
        assert lg._dropped == {"gap-retry": 1}, "drop count must survive a failed flush"

    async def test_no_marker_when_nothing_was_dropped(self):
        lg = _logger(maxsize=10)
        session = "gap-none"
        lg.log(_event(lg, session, 0))
        queued = lg._queue.get_nowait()
        lg._queue.task_done()
        await lg._write_batch([queued])
        await lg._flush_gap_markers()

        replay = await lg.replay(session)
        assert [e for e in replay.events if e.reason_code == "audit_gap"] == []
