"""
TrustMediator evaluation harness (PRD §14).

Implements the P3 "Evaluation" phase deliverables:
  - a reusable benchmark harness (§14.1)
  - KPI measurement against the §14.2 targets
  - the per-module ablation study (§14.3), which is itself a research
    deliverable

Testbeds live under `benchmarks/testbeds/`. Each testbed declares which
ablation axes it can meaningfully exercise, so a run never reports a
number for a layer it did not actually vary.
"""

__all__ = ["harness", "testbeds"]
