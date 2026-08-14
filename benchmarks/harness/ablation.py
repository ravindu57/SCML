"""
Per-module ablation configuration (PRD §14.3).

The ablation is a research deliverable in its own right: it quantifies which
layer stops which attack class, and specifically the marginal contribution of
the memory integrity layer (§2.3, §6.5).

Layers are disabled by substituting a null implementation that satisfies the
same interface but makes no decision. Nothing in `trust_mediator/` branches on
"am I being benchmarked?" — the production code path under test is the real
one, which is what makes the numbers meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass

from trust_mediator.db.memory_repo import MemoryRepository
from trust_mediator.models.context_envelope import (
    ContextEnvelope,
    Provenance,
    ScanResult,
    ScanVerdict,
)
from trust_mediator.models.memory_record import (
    MemoryReadRequest,
    MemoryRecord,
    MemoryStatus,
    MemoryWriteRequest,
)
from trust_mediator.modules.memory_integrity.consistency_checker import ConsistencyReport
from trust_mediator.modules.memory_integrity.layer import MemoryReadResult, MemoryWriteResult

#: Every ablation axis the harness knows about. A testbed declares the subset
#: it can actually exercise; the rest are reported N/A.
AXIS_SCANNER = "scanner"
AXIS_CONSISTENCY = "consistency"
AXIS_MEMORY_INTEGRITY = "memory_integrity"
AXIS_TRUST_ROUTER = "trust_router"
AXIS_TOOL_POLICY = "tool_policy"

ALL_AXES: tuple[str, ...] = (
    AXIS_SCANNER,
    AXIS_CONSISTENCY,
    AXIS_MEMORY_INTEGRITY,
    AXIS_TRUST_ROUTER,
    AXIS_TOOL_POLICY,
)


@dataclass(frozen=True)
class AblationConfig:
    """
    Which defence layers are active for a run.

    `undefended` (everything off) is the baseline the §14.2 "≥ 90% relative
    ASR reduction" target is measured against.
    """

    name: str
    scanner: bool = True
    consistency: bool = True
    memory_integrity: bool = True
    trust_router: bool = True
    tool_policy: bool = True

    def enabled(self, axis: str) -> bool:
        if axis not in ALL_AXES:
            raise ValueError(f"Unknown ablation axis: {axis!r}")
        return bool(getattr(self, axis))

    @property
    def disabled_axes(self) -> tuple[str, ...]:
        return tuple(a for a in ALL_AXES if not self.enabled(a))

    @property
    def is_undefended(self) -> bool:
        return not any(self.enabled(a) for a in ALL_AXES)


def memory_ablation_grid() -> list[AblationConfig]:
    """
    The §14.3 ablation grid for the memory-poisoning testbed.

    Axes varied here are the three that actually gate a memory write:
    the injection scanner (stage 2), the consistency checker (stage 3), and
    the memory integrity layer as a whole. Trust routing and tool policy do
    not sit on the memory write path — they are exercised by the AgentDojo /
    InjecAgent testbeds instead, and are reported N/A here.
    """
    return [
        AblationConfig("full_defence"),
        # Isolates what consistency checking + scoring contribute alone.
        AblationConfig("no_scanner", scanner=False),
        # Isolates what the injection scanner contributes alone.
        AblationConfig("no_consistency", consistency=False),
        # Both detectors off: only provenance scoring + threshold remain.
        AblationConfig("scoring_only", scanner=False, consistency=False),
        # Baseline: memory writes persist unvetted.
        AblationConfig(
            "undefended",
            scanner=False,
            consistency=False,
            memory_integrity=False,
            trust_router=False,
            tool_policy=False,
        ),
    ]


def injection_ablation_grid() -> list[AblationConfig]:
    """
    The §14.3 ablation grid for the InjecAgent testbed.

    Different axes from the memory grid, because a different path is under
    test. An indirect injection arrives as context and does its damage through
    a tool call, so the layers that gate it are the scanner (does the poisoned
    content get through?), trust routing (is tool output labelled untrusted at
    all?) and tool policy (may the agent call what the attacker asked for?).

    `no_tool_policy` is the important row: it isolates detection from
    enforcement, and shows how much of the defence survives when the scanner is
    the only thing standing in the way — which is the configuration most
    deployments actually run.
    """
    return [
        AblationConfig("full_defence"),
        # Detection off: what enforcement alone is worth.
        AblationConfig("no_scanner", scanner=False),
        # Enforcement off: what detection alone is worth.
        AblationConfig("no_tool_policy", tool_policy=False),
        # Tool output no longer labelled untrusted.
        AblationConfig("no_trust_router", trust_router=False),
        # Baseline: poisoned context reaches the agent and every call proceeds.
        AblationConfig(
            "undefended",
            scanner=False,
            consistency=False,
            memory_integrity=False,
            trust_router=False,
            tool_policy=False,
        ),
    ]


# ── Null implementations used to switch a layer off ───────────────────────────


class NullScanner:
    """
    Ablation stub for §6.3. Satisfies the `InjectionScanner` surface used by
    the pipeline and the memory integrity layer, but never flags anything.
    """

    def scan(self, envelope: ContextEnvelope) -> ContextEnvelope:
        return envelope.model_copy(
            update={
                "scanner_verdict": ScanResult(
                    decision=ScanVerdict.ALLOW,
                    score=0.0,
                    rationale="scanner disabled (ablation)",
                ),
                "is_verified": True,
            }
        )

    async def scan_async(self, envelope: ContextEnvelope) -> ContextEnvelope:
        """
        The memory layer and pipeline call `scan_async`. Without this the stub
        would not satisfy the surface it claims to, and every ablation run with
        the scanner disabled would fail closed on an AttributeError instead of
        measuring an undefended path.
        """
        return self.scan(envelope)

    def scan_batch(self, envelopes: list[ContextEnvelope]) -> list[ContextEnvelope]:
        return [self.scan(e) for e in envelopes]


class NullConsistencyChecker:
    """Ablation stub for §6.5 stage 3 — reports every candidate as consistent."""

    def check(
        self, candidate_content: str, existing_records: list[MemoryRecord]
    ) -> ConsistencyReport:
        return ConsistencyReport()


class BypassMemoryLayer:
    """
    Ablation stub for §6.5 as a whole — the undefended baseline.

    Models an agent with ordinary long-term memory: every candidate write
    persists immediately as ACTIVE, and every read is served without
    verification. This is the behaviour TrustMediator exists to replace, and
    the denominator for relative ASR reduction.
    """

    def __init__(self, repo: MemoryRepository | None = None) -> None:
        self._repo = repo or MemoryRepository()

    async def vet_write(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        record = MemoryRecord(
            content=request.content,
            source_provenance=Provenance(
                source=request.source,
                uri=request.source_uri,
                session_id=request.session_id,
                agent_id=request.agent_id,
            ),
            trust_label=request.trust_label,
            status=MemoryStatus.ACTIVE,
            metadata=request.metadata,
        )
        await self._repo.save(record, agent_id=request.agent_id)
        return MemoryWriteResult(
            record=record,
            verdict="persist",
            score_breakdown={},
            blocked=False,
        )

    async def verify_read(self, request: MemoryReadRequest) -> MemoryReadResult:
        record = await self._repo.get(request.memory_id)
        if record is None:
            return MemoryReadResult(
                record=None, verified=False, withheld=True, reason="memory_not_found"
            )
        return MemoryReadResult(record=record, verified=True)
