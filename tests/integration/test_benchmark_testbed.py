"""
Integration test for the memory-poisoning testbed (PRD §14.1).

Runs the real testbed end-to-end against the real mediator on a small corpus
subset — enough to prove the run path, the ablation switching, and the
success criteria work, without the runtime of a full grid.
"""

from __future__ import annotations

import pytest

from benchmarks.harness.ablation import AblationConfig
from benchmarks.harness.metrics import compute_metrics
from benchmarks.harness.runner import BenchmarkRunner
from benchmarks.testbeds.memory_poisoning import MemoryPoisoningTestbed
from benchmarks.testbeds.memory_poisoning.corpus import ATTACK_CASES, BENIGN_CASES
from trust_mediator.db.base import Base, create_all_tables, engine


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True, scope="module")
async def setup_db():
    await create_all_tables()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def _small_testbed() -> MemoryPoisoningTestbed:
    """A high-signal subset: one clearly-injected write, one read-path case,
    one plain benign entry, one instruction-shaped benign entry."""
    attacks = [
        next(c for c in ATTACK_CASES if c.id == "ovr-01"),
        next(c for c in ATTACK_CASES if c.path == "read"),
    ]
    benign = [
        next(c for c in BENIGN_CASES if not c.adversarial_to_filter),
        next(c for c in BENIGN_CASES if c.adversarial_to_filter),
    ]
    return MemoryPoisoningTestbed(attack_cases=attacks, benign_cases=benign)


@pytest.mark.asyncio
class TestMemoryPoisoningTestbed:
    async def test_undefended_baseline_lets_every_attack_through(self):
        """The baseline must be genuinely undefended, or relative ASR
        reduction (§14.2) is measured against the wrong denominator."""
        testbed = _small_testbed()
        result = await testbed.run(
            AblationConfig(
                "undefended",
                scanner=False,
                consistency=False,
                memory_integrity=False,
                trust_router=False,
                tool_policy=False,
            ),
            run_id="itest_undef",
        )
        metrics = compute_metrics(result)
        assert metrics.total_attacks == 2
        assert metrics.asr == 1.0

    async def test_full_defence_blocks_an_obvious_injection(self):
        testbed = _small_testbed()
        result = await testbed.run(AblationConfig("full_defence"), run_id="itest_full")
        by_id = {o.case_id: o for o in result.outcomes}
        assert by_id["ovr-01"].attack_succeeded is False
        assert by_id["ovr-01"].blocked is True

    async def test_legitimate_standing_instruction_is_not_a_false_positive(self):
        """A user preference phrased as a standing instruction must persist —
        blocking it is lost utility, not a security win."""
        testbed = _small_testbed()
        result = await testbed.run(AblationConfig("full_defence"), run_id="itest_fp")
        adversarial_benign = [
            o for o in result.benign if o.case_id.startswith("ben-")
        ]
        assert adversarial_benign
        assert all(not o.is_false_positive for o in adversarial_benign)

    async def test_runner_reports_unsupported_axes_as_na(self):
        """Trust routing and tool policy are not on the memory write path;
        crediting them here would be a false claim."""
        runner = BenchmarkRunner(_small_testbed())
        report = await runner.run_grid([AblationConfig("full_defence")])
        assert "trust_router" in report.results[0].unsupported_axes
        assert "tool_policy" in report.results[0].unsupported_axes

    async def test_report_captures_settings_for_reproducibility(self):
        runner = BenchmarkRunner(_small_testbed())
        report = await runner.run_grid([AblationConfig("full_defence")])
        assert "memory_integrity_threshold" in report.mediator_settings
        assert "scanner_backend" in report.mediator_settings
