"""
scml - middleware layer secure | LangChain Integration
=====================================================
Drop-in security guard for any LangChain agent or chain.

Usage
-----
    from trust_mediator.integrations.langchain_guard import TrustMediatorGuard

    guard = TrustMediatorGuard(
        api_url="http://localhost:8000",
        api_key="sk-your-key",          # omit if dev mode (no key configured)
        agent_id="my-langchain-agent",
        session_id="user-session-abc",
    )

    # Wrap any LangChain agent
    agent = initialize_agent(tools, llm, callbacks=[guard])

    # Or wrap a chain
    chain = LLMChain(llm=llm, prompt=prompt, callbacks=[guard])

What it intercepts
------------------
* on_tool_start  → POST /v1/mediate/tool-call  (authorises the call)
* on_tool_end    → POST /v1/mediate/context    (scans tool outputs for injection)
* on_llm_start   → POST /v1/mediate/context    (scans prompts before the LLM sees them)
* on_chain_end   → POST /v1/mediate/output     (audits the final output)

Enforcement — read this before relying on it
--------------------------------------------
LangChain's callback API is **notification-only**: a handler is told what
happened but cannot alter a prompt, a tool result or a chain output in flight.
So the hooks above give you scanning, policy verdicts and a complete audit
trail, but on their own they do not stop anything.

There are exactly two enforcement points:

* ``strict=True`` — a block, an approval gate or an unrecognised verdict raises
  ``TrustMediatorError``, which aborts the run. Coarse, but real.
* ``guard.redact(text)`` — returns the redacted text for you to substitute.
  Call it on your final answer; ``on_chain_end`` cannot do this for you.

Where you need content blocked or rewritten rather than merely observed, use
the wrapper adapters (``MediatedRetriever`` / ``MediatedTool``) or call the
REST API directly and branch on the decision.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Union

from trust_mediator.client import SCMLClient, Verdict, classify_decision

logger = logging.getLogger(__name__)

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    # Graceful degradation: still importable, just logs a warning
    _LANGCHAIN_AVAILABLE = False
    BaseCallbackHandler = object  # type: ignore
    LLMResult = Any  # type: ignore


class TrustMediatorError(RuntimeError):
    """Raised when TrustMediator blocks an action in strict mode."""


class TrustMediatorGuard(BaseCallbackHandler):
    """
    LangChain callback handler that routes all agent actions through the
    scml - middleware layer secure API.

    Parameters
    ----------
    api_url : str
        Base URL of the TrustMediator API (default: http://localhost:8000)
    api_key : str | None
        X-API-Key header value. Leave None if dev mode has no keys configured.
    agent_id : str
        Identifies this agent in audit logs and policy lookups.
    session_id : str | None
        Groups all events under one audit session. Auto-generated if not set.
    strict : bool
        If True, raises TrustMediatorError when a request is blocked or gated.
        If False (default), logs a warning and continues.
    timeout : float
        HTTP request timeout in seconds (default 5).
    arg_trust_label : str | None
        Trust label attached to tool arguments, enabling the untrusted-argument
        rule (FR-PE-04). Defaults to "untrusted_data" because an agent's tool
        inputs are composed by the model after it has read retrieved and
        tool-returned content.

        Note the consequence: with the default policy
        (`untrusted_arg_policy: require_approval`) every tool call will come
        back require_approval. That is the policy engine correctly reporting
        that your agent acts on model-composed arguments — tune
        `untrusted_arg_policy` per agent in your policy file rather than
        disabling the label. Set to None only if tool arguments provably derive
        from the authenticated user query alone.
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        api_key: str | None = None,
        agent_id: str = "langchain-agent",
        session_id: str | None = None,
        strict: bool = False,
        timeout: float = 5.0,
        arg_trust_label: str | None = "untrusted_data",
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            logger.warning(
                "langchain-core not installed. Install with: pip install langchain-core"
            )

        super().__init__()
        self.api_url   = api_url.rstrip("/")
        self.agent_id  = agent_id
        self.session_id = session_id or f"lc-{uuid.uuid4().hex[:12]}"
        self.strict    = strict
        self.timeout   = timeout
        self.arg_trust_label = arg_trust_label

        # Transport lives in the SDK client (trust_mediator.client). The guard
        # keeps its own stats and strict-mode semantics on top of it, and
        # passes fail_open=True because a callback that raises on an
        # unreachable mediator would abort the agent run on a network blip —
        # the guard reports transport failures through stats["errors"] instead.
        self._client = SCMLClient(
            self.api_url, api_key, agent_id=agent_id, timeout=timeout
        )
        self._headers: dict[str, str] = self._client.headers

        # Stats available for inspection after a run
        self.stats: dict[str, int] = {
            "allowed": 0,
            "blocked": 0,
            "escalated": 0,
            "approval_required": 0,
            "redacted": 0,                 # enforced via redact()
            "redactions_unenforced": 0,    # seen in a callback, could not apply
            "unknown": 0,
            "errors": 0,
        }

        if not arg_trust_label:
            logger.warning(
                "[TrustMediator] arg_trust_label disabled — tool arguments will "
                "be sent unlabelled and the untrusted-argument rule (FR-PE-04) "
                "cannot fire."
            )

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _post(self, path: str, payload: dict) -> dict:
        """
        Synchronous HTTP POST (LangChain callbacks are synchronous).

        Delegates transport to the SDK client and preserves this class's
        contract: transport failures come back as ``{"decision": "error"}``
        and are counted, rather than raising and aborting the agent run.
        """
        result = self._client.request("POST", path, payload, fail_open=True)
        if result.get("decision") == "error":
            self.stats["errors"] += 1
        return result

    def _handle_decision(self, result: dict, context: str) -> None:
        """Log the decision and raise if strict mode is on."""
        decision = result.get("decision", "").lower()
        # Classification is shared with the SDK client so the guard and a
        # direct API caller can never disagree about what a verdict means.
        verdict = classify_decision(decision)

        if verdict is Verdict.ALLOW:
            self.stats["allowed"] += 1
            logger.debug("[TrustMediator] %s → %s", context, decision.upper())

        elif verdict is Verdict.BLOCK:
            self.stats["blocked"] += 1
            reason  = result.get("reason", result.get("rationale", "—"))
            patterns = result.get("patterns_matched", [])
            msg = f"[TrustMediator] BLOCKED — {context} | reason: {reason}"
            if patterns:
                msg += f" | patterns: {patterns}"
            logger.warning(msg)
            if self.strict:
                raise TrustMediatorError(msg)

        # The policy engine reports approval gates as require_approval,
        # require_approval.irreversible, require_approval.high_impact or
        # require_approval.untrusted_arg (PolicyDecisionCode). These used to
        # match no branch here, so a gated call was silently counted as
        # nothing and — worse — did not raise under strict mode. An agent
        # would sail straight through a gate policy had closed on an
        # irreversible action (FR-PE-03).
        elif verdict is Verdict.APPROVAL_REQUIRED:
            self.stats["approval_required"] += 1
            reason = result.get("reason", "—")
            msg = (
                f"[TrustMediator] APPROVAL REQUIRED — {context} | "
                f"reason: {reason} | approval_id: {result.get('approval_id')}"
            )
            logger.warning(msg)
            if self.strict:
                raise TrustMediatorError(msg)

        elif verdict is Verdict.ESCALATE:
            self.stats["escalated"] += 1
            logger.warning("[TrustMediator] ESCALATE — %s | requires human review", context)

        elif verdict is Verdict.ERROR:
            pass  # transport failure — already counted in _post

        else:
            # Never silently ignore an unrecognised verdict: that is how the
            # approval gap above went unnoticed. QUARANTINE lands here too —
            # the guard has no memory-write hook, so a quarantine verdict
            # arriving through a callback is genuinely unexpected.
            self.stats["unknown"] += 1
            logger.warning(
                "[TrustMediator] UNRECOGNISED decision %r — %s | treating as unsafe",
                decision, context,
            )
            if self.strict:
                raise TrustMediatorError(
                    f"[TrustMediator] unrecognised decision {decision!r} for {context}"
                )

    # ── LangChain callback hooks ───────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Intercept tool calls and check against the policy allowlist."""
        tool_name = serialized.get("name", "unknown_tool")

        # Prefer LangChain's structured `inputs` over the flattened string.
        #
        # Wrapping everything as {"input": "<raw string>"} means the arguments
        # never match a declared argument_schema, so any allow-listed tool with
        # a schema was denied deny.schema_violation before any other rule could
        # run — FR-PE-02 unusable through this path, and FR-PE-04 masked behind
        # it. langchain-core passes `inputs` as a dict on modern versions;
        # older ones only give the flat string, in which case schema validation
        # genuinely cannot work here and the wrapper is the honest fallback.
        raw_inputs = kwargs.get("inputs")
        if isinstance(raw_inputs, dict) and raw_inputs:
            arguments: dict[str, Any] = dict(raw_inputs)
        else:
            arguments = {"input": input_str}

        payload: dict[str, Any] = {
            "session_id": self.session_id,
            "tool_name":  tool_name,
            "arguments":  arguments,
            "agent_id":   self.agent_id,
        }
        # Without argument trust labels the engine sees no untrusted arguments,
        # so the untrusted-argument rule (FR-PE-04) can never fire — the
        # strongest control it has is silently disabled. In an agent loop the
        # model composes tool inputs after reading retrieved and tool-returned
        # content, so by the taint rule (FR-TR-02) those inputs inherit the
        # most restrictive label of what produced them. Labelling them
        # untrusted is the accurate default, not a paranoid one.
        if self.arg_trust_label:
            payload["argument_trust_labels"] = {
                key: self.arg_trust_label for key in arguments
            }
        result = self._post("/v1/mediate/tool-call", payload)
        self._handle_decision(result, f"tool_call:{tool_name}")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Scan tool output for prompt injection before it re-enters the agent."""
        result = self._post("/v1/mediate/context", {
            "session_id": self.session_id,
            "content":    str(output),
            "source":     "tool_result",
            "agent_id":   self.agent_id,
        })
        self._handle_decision(result, "tool_output")

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Scan the assembled prompt before it is sent to the LLM."""
        for i, prompt in enumerate(prompts):
            result = self._post("/v1/mediate/context", {
                "session_id": self.session_id,
                "content":    prompt,
                "source":     "tool_result",
                "agent_id":   self.agent_id,
            })
            self._handle_decision(result, f"llm_prompt[{i}]")

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        """
        Audit the final chain output for PII, secrets and disallowed data flows.

        AUDIT ONLY — this cannot redact what the user sees. LangChain callbacks
        are notification-only: a handler receives `outputs` but nothing it does
        propagates back into the chain's return value. Call `guard.redact()` on
        your output for enforcement.

        Previously this posted the output and then discarded the response
        entirely — it checked a `decision` key that `/v1/mediate/output` does
        not return, so the check was always false and even a blocked
        exfiltration went unrecorded.
        """
        output_text = str(outputs.get("output", outputs.get("text", "")))
        if not output_text.strip():
            return

        result = self._post("/v1/mediate/output", {
            "session_id": self.session_id,
            "content":    output_text,
            "destination": "user",
        })
        if result.get("decision") == "error":
            return

        redactions = result.get("redactions_applied") or []
        if result.get("blocked"):
            self.stats["blocked"] += 1
            msg = (
                f"[TrustMediator] OUTPUT WOULD BE BLOCKED — "
                f"{result.get('block_reason', '—')} | NOT enforced: LangChain "
                f"callbacks cannot alter the chain result. Use guard.redact()."
            )
            logger.warning(msg)
            if self.strict:
                raise TrustMediatorError(msg)
        elif redactions:
            self.stats["redactions_unenforced"] += len(redactions)
            logger.warning(
                "[TrustMediator] %d redaction(s) identified in chain output but "
                "NOT applied — callbacks cannot alter the chain result. "
                "Use guard.redact() to enforce.",
                len(redactions),
            )
        else:
            self.stats["allowed"] += 1

    # ── Enforcing helper ───────────────────────────────────────────────────────

    def redact(self, text: str, destination: str = "user") -> str:
        """
        Redact an outbound response and return the safe text (FR-OR-01/02).

        Unlike the callback hooks this *is* enforcing, because the caller
        substitutes the return value:

            answer = agent.run(question)
            answer = guard.redact(answer)     # <- enforcement point
            print(answer)

        Raises TrustMediatorError in strict mode when policy blocks the flow
        outright (for example protected data heading to a disallowed sink).
        Returns the original text unchanged if the mediator is unreachable,
        which is the documented fail-open for a low-risk read path (§9) — set
        strict=True if you would rather fail closed.
        """
        result = self._post("/v1/mediate/output", {
            "session_id":  self.session_id,
            "content":     text,
            "destination": destination,
        })
        if result.get("decision") == "error":
            if self.strict:
                raise TrustMediatorError(
                    f"[TrustMediator] output mediation unreachable: {result.get('reason')}"
                )
            return text

        if result.get("blocked"):
            self.stats["blocked"] += 1
            msg = (
                f"[TrustMediator] OUTPUT BLOCKED — "
                f"{result.get('block_reason', 'disallowed data flow')}"
            )
            logger.warning(msg)
            if self.strict:
                raise TrustMediatorError(msg)
            return ""

        redactions = result.get("redactions_applied") or []
        if redactions:
            self.stats["redacted"] += len(redactions)
            logger.info("[TrustMediator] applied %d redaction(s)", len(redactions))
        else:
            self.stats["allowed"] += 1
        return result.get("content", text)

    def on_tool_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        logger.error("[TrustMediator] Tool raised error: %s", error)

    def summary(self) -> str:
        """Return a human-readable summary of this session's security stats."""
        s = self.stats
        line = (
            f"TrustMediator session={self.session_id} | "
            f"allowed={s['allowed']} "
            f"blocked={s['blocked']} "
            f"approval_required={s['approval_required']} "
            f"escalated={s['escalated']} "
            f"redacted={s['redacted']} "
            f"errors={s['errors']}"
        )
        if s["redactions_unenforced"]:
            line += (
                f" | WARNING: {s['redactions_unenforced']} redaction(s) identified "
                f"in chain output but not applied — call guard.redact()"
            )
        if s["unknown"]:
            line += f" | WARNING: {s['unknown']} unrecognised verdict(s)"
        return line
