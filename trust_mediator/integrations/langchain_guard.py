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
* on_tool_start  → POST /v1/mediate/tool-call  (blocks unauthorised tools)
* on_tool_end    → POST /v1/mediate/context    (scans tool outputs for injection)
* on_llm_start   → POST /v1/mediate/context    (scans prompts before LLM sees them)
* on_chain_end   → POST /v1/mediate/output     (redacts PII/secrets in final output)
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Union

import httpx

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
        If True, raises TrustMediatorError when a request is blocked.
        If False (default), logs a warning and continues.
    timeout : float
        HTTP request timeout in seconds (default 5).
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        api_key: str | None = None,
        agent_id: str = "langchain-agent",
        session_id: str | None = None,
        strict: bool = False,
        timeout: float = 5.0,
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

        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["X-API-Key"] = api_key

        # Stats available for inspection after a run
        self.stats: dict[str, int] = {
            "allowed": 0, "blocked": 0, "escalated": 0, "errors": 0
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _post(self, path: str, payload: dict) -> dict:
        """Synchronous HTTP POST (LangChain callbacks are synchronous)."""
        try:
            r = httpx.post(
                f"{self.api_url}{path}",
                json=payload,
                headers=self._headers,
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            logger.error("TrustMediator API error: %s %s", e.response.status_code, e.response.text)
            self.stats["errors"] += 1
            return {"decision": "error", "reason": str(e)}
        except Exception as e:
            logger.error("TrustMediator unreachable: %s", e)
            self.stats["errors"] += 1
            return {"decision": "error", "reason": str(e)}

    def _handle_decision(self, result: dict, context: str) -> None:
        """Log the decision and raise if strict mode is on."""
        decision = result.get("decision", "").lower()

        if decision in ("allow", "persist", "transform"):
            self.stats["allowed"] += 1
            logger.debug("[TrustMediator] %s → %s", context, decision.upper())

        elif decision in ("block", "reject", "deny") or decision.startswith("deny"):
            self.stats["blocked"] += 1
            reason  = result.get("reason", result.get("rationale", "—"))
            patterns = result.get("patterns_matched", [])
            msg = f"[TrustMediator] BLOCKED — {context} | reason: {reason}"
            if patterns:
                msg += f" | patterns: {patterns}"
            logger.warning(msg)
            if self.strict:
                raise TrustMediatorError(msg)

        elif decision == "escalate":
            self.stats["escalated"] += 1
            logger.warning("[TrustMediator] ESCALATE — %s | requires human review", context)

    # ── LangChain callback hooks ───────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Intercept tool calls and check against the policy allowlist."""
        tool_name = serialized.get("name", "unknown_tool")
        result = self._post("/v1/mediate/tool-call", {
            "session_id": self.session_id,
            "tool_name":  tool_name,
            "arguments":  {"input": input_str},
            "agent_id":   self.agent_id,
        })
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
        """Scan the final chain output for PII/secrets before it reaches the user."""
        output_text = str(outputs.get("output", outputs.get("text", "")))
        if not output_text.strip():
            return
        result = self._post("/v1/mediate/output", {
            "session_id": self.session_id,
            "content":    output_text,
            "destination": "user",
        })
        decision = result.get("decision", "").lower()
        if decision not in ("error", ""):
            self._handle_decision({"decision": "allow"}, "chain_output")

    def on_tool_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        logger.error("[TrustMediator] Tool raised error: %s", error)

    def summary(self) -> str:
        """Return a human-readable summary of this session's security stats."""
        return (
            f"TrustMediator session={self.session_id} | "
            f"allowed={self.stats['allowed']} "
            f"blocked={self.stats['blocked']} "
            f"escalated={self.stats['escalated']} "
            f"errors={self.stats['errors']}"
        )
