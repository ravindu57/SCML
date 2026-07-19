"""
Regression test: the audit hash chain must stay linear when multiple
workers (separate AuditLogger instances, no shared memory) write events
for the same session (FR-AL-01).

Before the fix, each worker kept its own in-memory seq/hash state, so a
multi-worker deployment produced duplicate seq_nos and a forked chain —
replay reported chain_valid=False for perfectly legitimate traffic.
"""

from __future__ import annotations

from trust_mediator.db.base import create_all_tables
from trust_mediator.models.audit_event import AuditDecision, AuditModule
from trust_mediator.modules.audit_log.logger import AuditLogger


async def test_two_workers_one_session_chain_stays_valid():
    await create_all_tables()

    # Two independent logger instances = two uvicorn workers
    worker_a = AuditLogger()
    worker_b = AuditLogger()

    session_id = "multiworker-chain-test"
    for i in range(6):
        worker = worker_a if i % 2 == 0 else worker_b
        event = worker.make_event(
            session_id=session_id,
            module=AuditModule.TOOL_POLICY,
            decision=AuditDecision.ALLOW,
            reason_code=f"step-{i}",
        )
        # Write directly (bypassing the queue) to interleave deterministically
        await worker._write(event)

    replay = await worker_a.replay(session_id)
    assert replay.event_count == 6
    assert replay.chain_valid, f"chain broken: {replay.integrity_issues}"
    seqs = [e.seq_no for e in replay.events]
    assert seqs == [1, 2, 3, 4, 5, 6], f"non-linear seq_nos: {seqs}"
