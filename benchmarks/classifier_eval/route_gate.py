"""
Fast, CPU-bound routing gate for the classifier protocol (FR-SC-08, NFR-PERF-01).

The committed measurement (`benchmarks/results/classifier_llm.md`) shows the
only backend that separates the classes — a hosted LLM, held-out ROC-AUC 0.72 —
fails NFR-PERF-01 at p95 ≈ 2.2 s per payload, so it cannot sit on the
synchronous mediation path. The untested combination it points at is a *cheap
syntactic gate that routes only genuinely ambiguous payloads to the LLM*, never
the request path.

This module implements that gate and, more importantly, the *measurement* of it:
a gate only helps if it routes most benign payloads away (sparing the FPR risk
*and* the latency of an LLM call) while preserving the attacks for the LLM
(so the LLM's recall is not undermined by the filter in front of it).

Design rule (FR-SC-06): the gate is derived from the *linguistic concept* of an
instruction embedded in data — an imperative/command addressed to an assistant —
never from inspecting the evaluation corpus. The vocabulary is a closed class of
command verbs and directive markers chosen to describe tool actions, not to
match any attack list.

This is an architecture measurement, not a shipped detector. The numbers it
produces are honest bucket statistics (`fraction routed away`,
`attack_preserved`, `llm_call_fraction`) over the external held-out corp; a
gate that routes everything to the LLM is correctly shown to save nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


#: Closed-class verbs describing a tool/control action — the imperative frame of
#: an embedded instruction, addressed to an assistant, not domain data.
_COMMAND_VERBS = frozenset(
    {
        "grant", "create", "send", "transfer", "disable", "enable", "delete",
        "add", "invite", "share", "post", "reveal", "approve", "schedule",
        "cancel", "update", "set", "reset", "unlock", "activate", "deactivate",
        "execute", "run", "override", "forget", "ignore", "disregard", "omit",
        "forward", "email", "pay", "purchase", "book", "confirm", "change",
        "revoke", "remove", "allow", "grant", "uninstall",
    }
)

#: Directive separators that make an otherwise-plain noun phrase an instruction.
_DIRECTIVE = re.compile(
    r"(?i)(\bplease\b|\bkindly\b|\bnow\b|\bimmediately\b|\burgently\b)|"
    r"(\byou\s+(must|should|will|shall|need|can|could|are))\b|"
    r"(\bI\s+need\s+you\s+to\b)|\b(instruction|remember|instead|from\s+now\s+on)\b"
)

#: A command verb acting on an object in the same clause — the strongest frame.
_WORD = re.compile(r"[a-z']+")


@dataclass(frozen=True)
class GateVerdict:
    """What the routing gate decided for one payload."""

    route_to_llm: bool
    reasons: tuple[str, ...] = ()


class SyntacticRouteGate:
    """Concept-based, CPU-bound gate between the request path and the LLM.

    Internationalized/embedded data passes through (``route_to_llm=False``);
    any command construction routes to the LLM (``route_to_llm=True``). The
    boundary is deliberately coarse so it does not drop attacks: an attack that
    contains *any* instruction frame is preserved for the LLM, and only clearly
    data-only payloads are spared a call.
    """

    def route(self, text: str) -> GateVerdict:
        # This payload is *tool output* (JSON): the injected instruction lives
        # *inside* a quoted value, not in the surrounding frame. So unlike the
        # scaffold, this gate does NOT strip quoted spans — stripping removes
        # the very signal it is looking for. Search the whole payload.
        lowered = text.lower()
        tokens = set(_WORD.findall(lowered))
        verbs = tokens & _COMMAND_VERBS
        reasons: list[str] = []
        if verbs:
            reasons.append("command:" + ",".join(sorted(verbs)))
        if _DIRECTIVE.search(text):
            reasons.append("directive")
        # A payload with neither a command verb nor any directive marker is
        # treated as data and spared the LLM call.
        return GateVerdict(route_to_llm=bool(reasons), reasons=tuple(reasons))

    # The rest of the BaseClassifier surface is not needed for a routing gate,
    # but timing symmetry with the scorer is useful: a scalar latency proxy.
    def scan_ms(self, text: str) -> float:
        import time as _t

        t0 = _t.perf_counter()
        self.route(text)
        return (_t.perf_counter() - t0) * 1000.0
