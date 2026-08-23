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


#: A value must be this long before a bare substring match counts as evidence
#: that it came from tool output. Set from a measured false positive: with a
#: threshold of 5, ``subject="Notes"`` was labelled untrusted because the word
#: "notes" appeared in the attacker's sentence. Common words collide by chance,
#: and every collision refuses a legitimate action.
MIN_TAINT_MATCH = 12

#: Substrings that make a coincidence implausible regardless of length. An
#: address or URL appearing in both the tool output and the argument is the
#: exfiltration case this rule exists to catch, and is short enough to slip
#: under the length bar.
DISTINCTIVE_MARKERS = ("@", "://")


def conversation_is_tainted(messages: list[Any]) -> bool:
    """True once a tool result has entered the conversation.

    AgentDojo delivers every injection through a tool result, so this is the
    moment after which the model may be repeating an attacker's instruction.
    """
    return any(_role(m) == "tool" for m in messages)


def tool_output_seen(messages: list[Any]) -> str:
    """Every tool result so far, lowercased, as one blob to match against."""
    parts: list[str] = []
    for message in messages:
        if _role(message) != "tool":
            continue
        parts.append(_message_text(message))
    return "\n".join(parts).lower()


#: Keys a content block might carry its text under. AgentDojo's blocks are
#: ``{"type": "text", "content": "..."}`` — note **content**, not ``text``.
#: Reading only ``text`` returned "" for every message, so no argument ever
#: matched, no argument was ever labelled untrusted, and FR-PE-04 could not
#: fire in a single real run. The failure was silent: an empty corpus looks
#: exactly like a conversation with nothing untrusted in it.
_TEXT_KEYS = ("content", "text")


def _message_text(message: Any) -> str:
    content = _get(message, "content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks = []
        for block in content:
            for key in _TEXT_KEYS:
                value = _get(block, key)
                if isinstance(value, str):
                    chunks.append(value)
                    break
        return "\n".join(chunks)
    return str(content or "")


def derived_arguments(args: dict[str, Any], tool_output: str) -> dict[str, str]:
    """Label only the arguments whose values appear in prior tool output.

    Conversation-level taint — "any tool result has arrived, so everything
    after it is untrusted" — refuses any task that writes after reading.
    Measured: it cost `user_task_12` and `user_task_13` all of their utility,
    because both legitimately create a file or a calendar event having first
    read something.

    Matching the value against what the tools actually returned separates
    "the model is echoing an attacker's payload" from "the model is repeating
    the user's own instruction". It is an approximation of dataflow, not
    dataflow: an injection that tells the model to *construct* a value rather
    than copy one — concatenating an address, or spelling it out — evades this.
    That is a known limit, and the reason a real implementation tracks
    provenance at the source rather than inferring it here.
    """
    if not tool_output:
        return {}
    labels: dict[str, str] = {}
    for name, value in args.items():
        text = str(value).strip().lower()
        if not text or text not in tool_output:
            continue
        distinctive = len(text) >= MIN_TAINT_MATCH or any(
            marker in text for marker in DISTINCTIVE_MARKERS
        )
        if distinctive:
            labels[name] = "untrusted_data"
    return labels


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

    @property
    def needs_approval(self) -> bool:
        """A verdict a human could have satisfied, as opposed to a hard deny.

        The benchmark has no approver, so `require_approval` is counted as a
        refusal — anything else would be the FR-PE-03 error of reading it as an
        allow. But that makes the measured utility a *floor*: in a deployment
        with a reviewer, some of these become completed work. Separating the two
        is what turns "our score is unfairly low" into a number.
        """
        return self.decision.startswith("require_approval")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        verdict = "ALLOW" if self.allowed else ("APPROVE?" if self.needs_approval else "DENY")
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

    def __init__(
        self,
        client: Any,
        agent_id: str,
        *,
        session_id: str,
        auto_approve: bool = False,
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        # Stand in for a human reviewer. Off by default, because a benchmark
        # that silently approves its own gates is measuring nothing. Turned on
        # deliberately, it answers a question the default cannot: how much of
        # the utility loss is a hard refusal, and how much is work waiting on
        # someone to click approve.
        self._auto_approve = auto_approve
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

        tool_output = tool_output_seen(messages)
        out: list[tuple[Any, ScmlDecision]] = []
        for call in _tool_calls(messages[-1]):
            decision = self._mediate(call, tool_output=tool_output)
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

    def _mediate(self, call: Any, *, tool_output: str) -> ScmlDecision:
        tool_name = str(getattr(call, "function", None) or _get(call, "function") or "")
        args = getattr(call, "args", None)
        if args is None:
            args = _get(call, "args") or {}
        args = dict(args) if isinstance(args, dict) else {}

        irreversible, high_impact = classify_tool(tool_name)

        # Two filters, both measured rather than assumed.
        #
        # Only tools that can *act* are checked at all: a read has no side
        # effect and no egress, so refusing it costs utility and buys no
        # security — the mediator gates actions and egress, not beliefs, the
        # same rule that makes poisoned memory inert. Labelling every tool put
        # 4 of 6 denials on reads.
        #
        # Then only the arguments that actually came from tool output are
        # labelled, rather than all of them. Blanket labelling refuses any task
        # that writes after reading, which cost user_task_12 and user_task_13
        # all their utility.
        acts = irreversible or high_impact
        labels = derived_arguments(args, tool_output) if acts else {}

        result = self._client.mediate_tool_call(
            self._session_id,
            tool_name,
            args,
            agent_id=self._agent_id,
            argument_trust_labels=labels,
            is_irreversible=irreversible,
            is_high_impact=high_impact,
        )
        decision = ScmlDecision(
            tool=tool_name,
            allowed=bool(result.allowed),
            decision=str(result.decision or ""),
            reason=str(result.reason or ""),
        )
        if self._auto_approve and decision.needs_approval:
            # A reviewer said yes. The verdict string is left untouched so the
            # record still shows the gate fired and who cleared it, rather than
            # looking like the call was allowed outright.
            decision.allowed = True
        return decision


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
