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
    """Mediates every tool call through SCML before AgentDojo executes it.

    Deliberately not a subclass of ``BasePipelineElement``: importing AgentDojo
    here would drag langchain and four provider SDKs into a repo whose
    ``client-install`` CI job exists to keep them out. AgentDojo only requires
    a ``query`` method with the right shape, so duck typing is enough. The
    benchmark runner, which does have AgentDojo installed, wraps this.
    """

    def __init__(
        self,
        client: Any,
        agent_id: str,
        *,
        session_id: str,
        abort_cls: type[Exception],
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        # One session per task: the audit chain is per session, so sharing one
        # across tasks would interleave unrelated runs into a single hash chain
        # and make a replay meaningless as evidence for any one of them.
        self._session_id = session_id
        self._abort_cls = abort_cls
        self.decisions: list[ScmlDecision] = []

    @property
    def name(self) -> str:
        return "scml"

    @property
    def denied(self) -> list[ScmlDecision]:
        return [d for d in self.decisions if not d.allowed]

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: list[Any] | None = None,
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, list[Any], dict[str, Any]]:
        messages = list(messages or [])
        extra_args = extra_args or {}
        if not messages:
            return query, runtime, env, messages, extra_args

        last = messages[-1]
        if _role(last) != "assistant":
            return query, runtime, env, messages, extra_args

        tainted = conversation_is_tainted(messages)

        for call in _tool_calls(last):
            decision = self._mediate(call, tainted=tainted)
            self.decisions.append(decision)
            if not decision.allowed:
                raise self._abort_cls(
                    f"SCML denied {decision.tool}: {decision.decision} — {decision.reason}",
                    messages,
                    env,
                )

        return query, runtime, env, messages, extra_args

    def _mediate(self, call: Any, *, tainted: bool) -> ScmlDecision:
        tool_name = str(getattr(call, "function", None) or _get(call, "function") or "")
        args = getattr(call, "args", None)
        if args is None:
            args = _get(call, "args") or {}
        args = dict(args) if isinstance(args, dict) else {}

        irreversible, high_impact = classify_tool(tool_name)
        labels = (
            {k: "untrusted_data" for k in args} if tainted else {}
        )

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
