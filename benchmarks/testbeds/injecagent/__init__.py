"""
InjecAgent testbed (PRD §14.1) — external validation of the injection defence.

The memory-poisoning corpus was written in-house, so a result against it
measures how well the detectors match text this project also wrote. This
testbed measures the mediator against 1054 indirect-injection cases authored by
a third party (Zhan et al., ACL Findings 2024) with no knowledge of it.

Usage:
    python -m benchmarks.cli --testbed injecagent
"""

from benchmarks.testbeds.injecagent.testbed import InjecAgentTestbed

__all__ = ["InjecAgentTestbed"]
