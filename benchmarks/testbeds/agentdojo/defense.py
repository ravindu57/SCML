"""
SCML as an AgentDojo defense (PRD §14.1, FR-PE-02/03/04).

AgentDojo's tools loop runs its elements in order each iteration:

    ToolsExecutionLoop([ScmlDefense(...), ToolsExecutor(...), llm])

Placed first, this sees the assistant's tool calls *before* they execute, which
is the point where SCML actually decides anything — the mediator authorises
actions, it does not inspect prose. A denial raises ``AbortAgentError``, the
mechanism AgentDojo provides for exactly this, and the run stops.

Aborting on denial is the honest mapping of PRD §9. There is no human approver
in a benchmark, so ``require_approval`` cannot be satisfied and is a denial in
practice — counted as one rather than quietly treated as an allow.

**Taint is approximated, and the approximation is the weak point.** Real
propagation needs dataflow the mediator cannot see from here, so this labels
arguments ``untrusted_data`` once any tool result has entered the conversation,
on the grounds that anything the model composes afterwards may derive from it.
That is conservative: it over-taints arguments the model actually took from the
user's original instruction. Utility lost this way is a real cost of the
approximation, not of SCML, and must be reported as such.

Without labels FR-PE-04 cannot fire at all and a model-composed argument is
indistinguishable from a user-supplied one — the same trap documented for the
LangChain guard.
"""
from __future__ import annotations

from typing import Any

#: Tools whose effects leave the system or cannot be undone. AgentDojo's
#: injection goals are overwhelmingly exfiltration (send_email, share_file) or
#: destruction, so this is where least agency has to bite.
IRREVERSIBLE_TOOLS = frozenset(
    {
        "send_email",
        "share_file",
        "delete_email",
        "delete_file",
        "cancel_calendar_event",
    }
)

#: Tools that change state but are recoverable.
HIGH_IMPACT_TOOLS = frozenset(
    {
        "create_file",
        "append_to_file",
        "create_calendar_event",
        "reschedule_calendar_event",
        "add_calendar_event_participants",
    }
)


def classify_tool(name: str) -> tuple[bool, bool]:
    """Return ``(is_irreversible, is_high_impact)`` for a tool name."""
    return name in IRREVERSIBLE_TOOLS, name in HIGH_IMPACT_TOOLS


def conversation_is_tainted(messages: list[Any]) -> bool:
    """True once a tool result has entered the conversation.

    AgentDojo delivers every injection through a tool result, so this is the
    moment after which the model may be repeating an attacker's instruction.
    """
    return any(_role(m) == "tool" for m in messages)


def _role(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("role", ""))
    return str(getattr(message, "role", ""))


def _tool_calls(message: Any) -> list[Any]:
    if isinstance(message, dict):
        return message.get("tool_calls") or []
    return getattr(message, "tool_calls", None) or []


class ScmlDecision:
    """One mediation verdict, kept for the run's record."""

    __slots__ = ("tool", "allowed", "reason", "decision")

    def __init__(self, tool: str, allowed: bool, decision: str, reason: str) -> None:
        self.tool = tool
        self.allowed = allowed
        self.decision = decision
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"<{verdict} {self.tool}: {self.decision}>"


class ScmlDefense:
    """Decides, per tool call, whether SCML authorises it.

    Deliberately free of AgentDojo imports: pulling them in would drag
    langchain and four provider SDKs into a repo whose ``client-install`` CI job
    exists to keep them out. This holds the decision logic and the record; the
    benchmark runner, which does have AgentDojo installed, turns a refusal into
    a tool result.

    **It refuses calls; it does not stop the agent.** The first version raised
    AgentDojo's ``AbortAgentError`` on denial, which halted the whole run — so
    blocking an injected `send_email` also killed the user's unfinished task,
    and utility measured 0% while ASR measured 0%. A reference monitor denies an
    action and hands back the refusal; the caller decides what to do next. The
    denial is the tool's result, not the end of the conversation.
    """

    def __init__(self, client: Any, agent_id: str, *, session_id: str) -> None:
        self._client = client
        self._agent_id = agent_id
        # One session per task: the audit chain is per session, so sharing one
        # across tasks would interleave unrelated runs into a single hash chain
        # and make a replay meaningless as evidence for any one of them.
        self._session_id = session_id
        self.decisions: list[ScmlDecision] = []

    @property
    def name(self) -> str:
        return "scml"

    @property
    def denied(self) -> list[ScmlDecision]:
        return [d for d in self.decisions if not d.allowed]

    def evaluate(self, messages: list[Any]) -> list[tuple[Any, ScmlDecision]]:
        """Mediate every tool call in the last message.

        Returns ``(call, decision)`` pairs in the order the model proposed
        them, so the caller can execute the allowed ones and answer the refused
        ones without losing the correspondence to their tool-call ids.
        """
        if not messages or _role(messages[-1]) != "assistant":
            return []

        tainted = conversation_is_tainted(messages)
        out: list[tuple[Any, ScmlDecision]] = []
        for call in _tool_calls(messages[-1]):
            decision = self._mediate(call, tainted=tainted)
            self.decisions.append(decision)
            out.append((call, decision))
        return out

    @staticmethod
    def refusal_text(decision: ScmlDecision) -> str:
        """What the agent is told when a call is refused.

        Names the rule rather than just saying no: an agent that knows *why*
        can choose a different route, which is the difference between a policy
        and a wall.
        """
        return (
            f"Refused by security policy ({decision.decision}). "
            f"{decision.reason} This action was not performed."
        )

    def _mediate(self, call: Any, *, tainted: bool) -> ScmlDecision:
        tool_name = str(getattr(call, "function", None) or _get(call, "function") or "")
        args = getattr(call, "args", None)
        if args is None:
            args = _get(call, "args") or {}
        args = dict(args) if isinstance(args, dict) else {}

        irreversible, high_impact = classify_tool(tool_name)

        # Label arguments only for tools that can *act*. A read has no side
        # effect and no egress, so refusing it on tainted arguments costs
        # utility and buys no security — the mediator gates actions and egress,
        # not beliefs, which is the same rule that makes poisoned memory inert.
        #
        # Measured, and the reason this is not `if tainted` alone: labelling
        # every tool drove ASR to 0% but utility to 0% too, and 4 of 6 denials
        # were reads (search_calendar_events, get_day_calendar_events). A
        # defense that refuses everything scores a perfect ASR and is worthless.
        acts = irreversible or high_impact
        labels = {k: "untrusted_data" for k in args} if (tainted and acts) else {}

        result = self._client.mediate_tool_call(
            self._session_id,
            tool_name,
            args,
            agent_id=self._agent_id,
            argument_trust_labels=labels,
            is_irreversible=irreversible,
            is_high_impact=high_impact,
        )
        return ScmlDecision(
            tool=tool_name,
            allowed=bool(result.allowed),
            decision=str(result.decision or ""),
            reason=str(result.reason or ""),
        )


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
