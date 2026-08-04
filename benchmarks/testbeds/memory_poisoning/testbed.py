"""
Memory-poisoning testbed execution (PRD §14.1, §14.2, §6.5).

Success criteria — deliberately defined in terms of agent-observable effect,
not internal verdicts:

  Write-path attack succeeds  when the poisoned record ends up ACTIVE, i.e.
                              readable, and therefore able to steer future
                              sessions. Quarantine and reject both count as
                              blocked (FR-MI-01, FR-MI-03).
  Read-path attack succeeds   when an already-ACTIVE poisoned record is served
                              back to the agent as verified (FR-MI-04).
  Benign case is a false      when a legitimate memory is anything other than
  positive                    persisted — a memory the agent can no longer
                              store is lost capability.

Isolation: every case runs in its own `agent_id` namespace, re-seeded with the
same trusted baseline. Cases therefore cannot influence one another, and the
consistency checker sees an identical baseline every time — so an ASR is not
an artifact of case ordering.
"""

from __future__ import annotations

import time

from benchmarks.harness.ablation import (
    ALL_AXES,
    AXIS_CONSISTENCY,
    AXIS_MEMORY_INTEGRITY,
    AXIS_SCANNER,
    AblationConfig,
    BypassMemoryLayer,
    NullConsistencyChecker,
    NullScanner,
)
from benchmarks.harness.case import AttackCase, BenignCase, CaseOutcome, SuiteResult
from benchmarks.testbeds.memory_poisoning.corpus import (
    ATTACK_CASES,
    BENIGN_CASES,
    SEEDED_FACTS,
)
from trust_mediator.db.memory_repo import MemoryRepository
from trust_mediator.models.context_envelope import Provenance, TrustLabel
from trust_mediator.models.memory_record import (
    MemoryReadRequest,
    MemoryRecord,
    MemoryStatus,
    MemoryWriteRequest,
)
from trust_mediator.modules.injection_scanner.scanner import InjectionScanner
from trust_mediator.modules.memory_integrity.consistency_checker import ConsistencyChecker
from trust_mediator.modules.memory_integrity.layer import MemoryIntegrityLayer


class MemoryPoisoningTestbed:
    """Purpose-built testbed for the §6.5 memory integrity layer."""

    name = "memory_poisoning"
    asr_kpi = "memory_poisoning_asr"
    #: Trust routing and tool policy do not sit on the memory write path, so
    #: this testbed cannot measure them. They are reported N/A.
    supported_axes = (AXIS_SCANNER, AXIS_CONSISTENCY, AXIS_MEMORY_INTEGRITY)

    def __init__(
        self,
        repo: MemoryRepository | None = None,
        attack_cases: list[AttackCase] | None = None,
        benign_cases: list[BenignCase] | None = None,
    ) -> None:
        self._repo = repo or MemoryRepository()
        # Overridable so tests can exercise the full run path on a small
        # subset. A published run always uses the complete corpus.
        self._attacks = attack_cases if attack_cases is not None else ATTACK_CASES
        self._benign = benign_cases if benign_cases is not None else BENIGN_CASES

    @property
    def unsupported_axes(self) -> tuple[str, ...]:
        return tuple(a for a in ALL_AXES if a not in self.supported_axes)

    # ── Layer construction per ablation config ────────────────────────────────

    def _build_layer(self, config: AblationConfig):
        if not config.memory_integrity:
            return BypassMemoryLayer(self._repo)
        return MemoryIntegrityLayer(
            repo=self._repo,
            scanner=InjectionScanner() if config.scanner else NullScanner(),
            checker=ConsistencyChecker() if config.consistency else NullConsistencyChecker(),
        )

    # ── Baseline seeding ──────────────────────────────────────────────────────

    async def _seed_baseline(self, agent_id: str) -> None:
        """
        Persist the trusted baseline facts directly as ACTIVE.

        Written through the repository rather than the integrity layer on
        purpose: these represent memory the agent already trusts, so putting
        them through vetting would measure the vetting of the baseline rather
        than of the attack.
        """
        for i, fact in enumerate(SEEDED_FACTS):
            record = MemoryRecord(
                content=fact,
                source_provenance=Provenance(
                    source="system_baseline", agent_id=agent_id
                ),
                trust_label=TrustLabel.TRUSTED_INSTRUCTION,
                status=MemoryStatus.ACTIVE,
                integrity_score=1.0,
                metadata={"seed_index": i},
            )
            await self._repo.save(record, agent_id=agent_id)

    # ── Case execution ────────────────────────────────────────────────────────

    async def _run_write_attack(
        self, layer, case: AttackCase, agent_id: str, config: AblationConfig
    ) -> CaseOutcome:
        request = MemoryWriteRequest(
            session_id=f"bench-{case.id}",
            content=case.content,
            source=case.source,
            trust_label=case.trust_label,
            agent_id=agent_id,
        )
        start = time.perf_counter()
        result = await layer.vet_write(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        succeeded = result.record.status == MemoryStatus.ACTIVE
        return CaseOutcome(
            case_id=case.id,
            kind="attack",
            family=case.family,
            config_name=config.name,
            latency_ms=elapsed_ms,
            verdict=result.verdict,
            attack_succeeded=succeeded,
            blocked=not succeeded,
            integrity_score=result.record.integrity_score,
            path="write",
            detail=result.record.quarantine_reason or result.verdict,
        )

    async def _run_read_attack(
        self, layer, case: AttackCase, agent_id: str, config: AblationConfig
    ) -> CaseOutcome:
        """
        FR-MI-04: a poisoned record that is already ACTIVE must still be caught
        when read back. Models a record written before a policy update.
        """
        planted = MemoryRecord(
            content=case.content,
            source_provenance=Provenance(source=case.source, agent_id=agent_id),
            trust_label=case.trust_label,
            status=MemoryStatus.ACTIVE,
            integrity_score=0.9,  # was trusted at write time
        )
        await self._repo.save(planted, agent_id=agent_id)

        request = MemoryReadRequest(
            session_id=f"bench-{case.id}",
            memory_id=planted.id,
            agent_id=agent_id,
            rescan=True,  # force re-verification (FR-MI-04)
        )
        start = time.perf_counter()
        result = await layer.verify_read(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        succeeded = bool(result.verified)
        return CaseOutcome(
            case_id=case.id,
            kind="attack",
            family=case.family,
            config_name=config.name,
            latency_ms=elapsed_ms,
            verdict="verified" if succeeded else (result.reason or "withheld"),
            attack_succeeded=succeeded,
            blocked=not succeeded,
            path="read",
            detail=result.reason,
        )

    async def _run_benign(
        self, layer, case: BenignCase, agent_id: str, config: AblationConfig
    ) -> CaseOutcome:
        request = MemoryWriteRequest(
            session_id=f"bench-{case.id}",
            content=case.content,
            source=case.source,
            trust_label=case.trust_label,
            agent_id=agent_id,
        )
        start = time.perf_counter()
        result = await layer.vet_write(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        persisted = result.record.status == MemoryStatus.ACTIVE
        return CaseOutcome(
            case_id=case.id,
            kind="benign",
            family="benign_adversarial" if case.adversarial_to_filter else "benign_plain",
            config_name=config.name,
            latency_ms=elapsed_ms,
            verdict=result.verdict,
            blocked=not persisted,
            integrity_score=result.record.integrity_score,
            path="write",
            detail=result.record.quarantine_reason or result.verdict,
        )

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self, config: AblationConfig, run_id: str) -> SuiteResult:
        outcomes: list[CaseOutcome] = []

        for case in self._attacks:
            agent_id = f"bench_{run_id}_{case.id}"
            await self._seed_baseline(agent_id)
            layer = self._build_layer(config)
            if case.path == "read":
                outcomes.append(await self._run_read_attack(layer, case, agent_id, config))
            else:
                outcomes.append(await self._run_write_attack(layer, case, agent_id, config))

        for benign in self._benign:
            agent_id = f"bench_{run_id}_{benign.id}"
            await self._seed_baseline(agent_id)
            layer = self._build_layer(config)
            outcomes.append(await self._run_benign(layer, benign, agent_id, config))

        return SuiteResult(
            testbed=self.name,
            config_name=config.name,
            outcomes=outcomes,
            unsupported_axes=self.unsupported_axes,
        )
