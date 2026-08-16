"""
SCML client SDK — the supported way to call a running mediator over HTTP.
=========================================================================

This is the *client* half of the thin waist: it speaks to a mediator that is
running somewhere else (another process, another host, another laptop). It
deliberately depends on nothing but ``httpx`` so that adding SCML to an agent
is a two-package install rather than a four-hundred-megabyte one. For the
in-process path with no HTTP hop, use ``trust_mediator.core.pipeline``
directly (requires the ``[embedded]`` extra).

Why this layer exists rather than callers using httpx themselves
---------------------------------------------------------------
The three mediation endpoints do not share a response shape:

  * ``/v1/mediate/context``    → ``decision``
  * ``/v1/mediate/tool-call``  → ``decision``
  * ``/v1/mediate/output``     → ``blocked`` / ``action_allowed``, no ``decision``
  * ``/v1/mediate/memory/write``→ ``verdict`` ("persist"/"quarantine"/"reject")
  * ``/v1/mediate/memory/read`` → ``verified`` / ``withheld``

A caller branching on ``result["decision"]`` is therefore correct for two
endpoints and silently wrong for three — an output block or a quarantined
memory write reads as "no decision key, carry on". ``MediationResult``
normalises all five onto one ``Verdict`` so a caller can write
``if not result.allowed`` once and have it mean the same thing everywhere.

Fail policy (PRD §9)
--------------------
Side-effect operations fail **closed**: if the mediator is unreachable,
``SCMLUnavailable`` is raised rather than returning something that looks like
an allow. This is the default and it is the safe one — an agent that treats a
transport error as permission is exactly the failure mode §9 exists to
prevent. Pass ``fail_open=True`` per call to opt out on a genuinely low-risk
read; every fail-open is logged locally, since by definition the audit log is
not reachable at that moment.

PRD references: FR-IG-01 (ingress), FR-PE-01..04 (tool policy),
FR-MI-01 (memory integrity), FR-OR-01/02 (output redaction), FR-AL-01 (audit).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 5.0


# ── Exceptions ────────────────────────────────────────────────────────────────

class SCMLError(RuntimeError):
    """Base class for every error raised by the SCML client."""


class SCMLUnavailable(SCMLError):
    """
    The mediator could not be reached, or returned a transport-level error.

    Raised instead of returning a result, because a caller that cannot tell
    "allowed" from "could not ask" will eventually treat the second as the
    first (PRD §9 fail-closed).
    """


class SCMLBlocked(SCMLError):
    """
    The mediator returned a verdict that is not an allow.

    Raised only by :meth:`MediationResult.raise_for_decision` and by calls made
    with ``raise_on_block=True``; the default is to return the result and let
    the caller branch.
    """

    def __init__(self, message: str, result: MediationResult | None = None) -> None:
        super().__init__(message)
        self.result = result


# ── Verdict normalisation ─────────────────────────────────────────────────────

class Verdict(str, Enum):
    """Normalised outcome, uniform across every endpoint."""

    ALLOW = "allow"
    BLOCK = "block"
    APPROVAL_REQUIRED = "approval_required"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"
    ERROR = "error"
    UNKNOWN = "unknown"


def classify_decision(decision: str | None) -> Verdict:
    """
    Map a raw server decision string onto a :class:`Verdict`.

    The branch order here is load-bearing and is preserved verbatim from the
    LangChain guard, where each case was added in response to a real escape:

    * ``require_approval`` arrives suffixed — ``require_approval.irreversible``,
      ``.high_impact``, ``.untrusted_arg`` (``PolicyDecisionCode``). Matching it
      exactly instead of by prefix once meant a gated call matched no branch at
      all, so an irreversible action sailed through a gate policy had closed
      (FR-PE-03).
    * ``deny`` likewise arrives suffixed (``deny.schema_violation`` and others).
    * An unrecognised verdict maps to ``UNKNOWN``, never to ``ALLOW``. Treating
      "I don't understand this answer" as permission is how the approval gap
      above went unnoticed in the first place.
    """
    d = (decision or "").lower()

    if d in ("allow", "persist", "transform", "verified"):
        return Verdict.ALLOW
    if d in ("block", "reject", "deny") or d.startswith("deny"):
        return Verdict.BLOCK
    if d.startswith("require_approval"):
        return Verdict.APPROVAL_REQUIRED
    if d == "escalate":
        return Verdict.ESCALATE
    if d in ("quarantine", "quarantined"):
        return Verdict.QUARANTINE
    if d in ("", "error"):
        return Verdict.ERROR
    return Verdict.UNKNOWN


@dataclass(frozen=True)
class MediationResult:
    """One mediation decision, normalised across endpoint response shapes."""

    verdict: Verdict
    decision: str
    reason: str = ""
    content: str | None = None
    trust_label: str | None = None
    score: float | None = None
    audit_ref: str = ""
    patterns_matched: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """
        True only for an explicit allow.

        Quarantine, escalate, approval-required, error and unknown are all
        *not* allowed. Callers gating a side effect should use this rather
        than ``verdict != Verdict.BLOCK``.
        """
        return self.verdict is Verdict.ALLOW

    def raise_for_decision(self) -> MediationResult:
        """Raise :class:`SCMLBlocked` unless the verdict is an allow."""
        if not self.allowed:
            raise SCMLBlocked(
                f"SCML {self.verdict.value}: {self.reason or self.decision}", self
            )
        return self

    # -- constructors per response shape ------------------------------------

    @classmethod
    def from_decision(cls, payload: dict[str, Any]) -> MediationResult:
        """For /context and /tool-call, which carry a ``decision`` field."""
        decision = str(payload.get("decision", ""))
        return cls(
            verdict=classify_decision(decision),
            decision=decision,
            # /context calls it `rationale`; /tool-call calls it `reason`.
            reason=str(payload.get("reason") or payload.get("rationale") or ""),
            content=payload.get("content"),
            trust_label=payload.get("trust_label"),
            score=payload.get("score"),
            audit_ref=str(payload.get("audit_ref", "")),
            patterns_matched=list(payload.get("patterns_matched") or []),
            raw=payload,
        )

    @classmethod
    def from_output(cls, payload: dict[str, Any]) -> MediationResult:
        """
        For /output, which reports ``blocked``/``action_allowed`` and has no
        ``decision`` key at all.
        """
        if payload.get("decision") == "error":
            return cls(verdict=Verdict.ERROR, decision="error",
                       reason=str(payload.get("reason", "")), raw=payload)
        blocked = bool(payload.get("blocked"))
        # action_allowed is absent on older responses; treat missing as allowed
        # so only an explicit False blocks.
        allowed = payload.get("action_allowed", True) is not False
        verdict = Verdict.BLOCK if (blocked or not allowed) else Verdict.ALLOW
        return cls(
            verdict=verdict,
            decision="block" if verdict is Verdict.BLOCK else "allow",
            reason=str(payload.get("block_reason", "")),
            content=payload.get("content"),
            audit_ref=str(payload.get("audit_ref", "")),
            raw=payload,
        )

    @classmethod
    def from_memory_write(cls, payload: dict[str, Any]) -> MediationResult:
        """For /memory/write, which reports ``verdict``, not ``decision``."""
        if payload.get("decision") == "error":
            return cls(verdict=Verdict.ERROR, decision="error",
                       reason=str(payload.get("reason", "")), raw=payload)
        verdict_str = str(payload.get("verdict", ""))
        return cls(
            verdict=classify_decision(verdict_str),
            decision=verdict_str,
            reason=str(payload.get("quarantine_reason", "")),
            score=payload.get("integrity_score"),
            audit_ref=str(payload.get("audit_ref", "")),
            raw=payload,
        )

    @classmethod
    def from_memory_read(cls, payload: dict[str, Any]) -> MediationResult:
        """For /memory/read, which reports ``verified``/``withheld``."""
        if payload.get("decision") == "error":
            return cls(verdict=Verdict.ERROR, decision="error",
                       reason=str(payload.get("reason", "")), raw=payload)
        withheld = bool(payload.get("withheld"))
        verified = bool(payload.get("verified"))
        verdict = Verdict.ALLOW if (verified and not withheld) else Verdict.BLOCK
        return cls(
            verdict=verdict,
            decision="withheld" if withheld else ("verified" if verified else "unverified"),
            reason=str(payload.get("reason", "")),
            content=payload.get("content"),
            score=payload.get("integrity_score"),
            raw=payload,
        )


# ── Shared request/response plumbing ──────────────────────────────────────────

class _BaseClient:
    """URL, headers and error handling shared by the sync and async clients."""

    def __init__(
        self,
        url: str = DEFAULT_API_URL,
        api_key: str | None = None,
        *,
        agent_id: str = "default",
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.url = url.rstrip("/")
        self.agent_id = agent_id
        self.timeout = timeout
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["X-API-Key"] = api_key

    @property
    def headers(self) -> dict[str, str]:
        """Request headers, including ``X-API-Key`` when a key was supplied."""
        return dict(self._headers)

    # -- error handling -----------------------------------------------------

    def _on_transport_error(self, exc: Exception, path: str, fail_open: bool) -> dict[str, Any]:
        """
        Convert a transport failure into either a raise or an error payload.

        Fail-closed is the default (PRD §9). ``fail_open`` is logged loudly
        because the audit log lives behind the very endpoint that just failed,
        so a local log line is the only record that a decision was skipped.
        """
        if isinstance(exc, httpx.HTTPStatusError):
            detail = f"{exc.response.status_code} {exc.response.text}"
        else:
            detail = str(exc)

        if not fail_open:
            logger.error("SCML mediator unreachable for %s: %s", path, detail)
            raise SCMLUnavailable(f"SCML mediator unreachable for {path}: {detail}") from exc

        logger.warning(
            "SCML FAIL-OPEN — %s could not be mediated (%s). Proceeding unmediated; "
            "this decision is NOT in the audit chain.", path, detail,
        )
        return {"decision": "error", "reason": detail}


class SCMLClient(_BaseClient):
    """
    Synchronous SCML client.

    >>> scml = SCMLClient("http://localhost:8000")
    >>> ctx = scml.mediate_context(session_id="s1", content=doc)
    >>> d = scml.mediate_tool_call(
    ...     session_id="s1", tool_name="release_container",
    ...     arguments={"id": "C-1"},
    ...     argument_trust_labels={"id": ctx.trust_label or "untrusted_data"},
    ... )
    >>> if not d.allowed:
    ...     raise RuntimeError(d.reason)
    """

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        fail_open: bool = False,
    ) -> dict[str, Any]:
        """Low-level escape hatch: returns the raw JSON body."""
        try:
            r = httpx.request(
                method,
                f"{self.url}{path}",
                json=payload,
                headers=self._headers,
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return self._on_transport_error(exc, path, fail_open)

    # -- mediation ----------------------------------------------------------

    def mediate_context(
        self,
        session_id: str,
        content: str,
        source: str = "tool_result",
        *,
        source_uri: str = "",
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        fail_open: bool = False,
    ) -> MediationResult:
        """Label and scan inbound content before an agent reads it (FR-IG-01)."""
        body = self.request("POST", "/v1/mediate/context", {
            "session_id": session_id,
            "content": content,
            "source": source,
            "source_uri": source_uri,
            "agent_id": agent_id or self.agent_id,
            "metadata": metadata or {},
        }, fail_open=fail_open)
        return MediationResult.from_decision(body)

    def mediate_tool_call(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        argument_trust_labels: dict[str, str] | None = None,
        agent_id: str | None = None,
        is_irreversible: bool = False,
        is_high_impact: bool = False,
        fail_open: bool = False,
    ) -> MediationResult:
        """
        Authorise a proposed tool call (FR-PE-01..04).

        ``argument_trust_labels`` is not optional in practice: without it the
        engine sees no untrusted arguments and the untrusted-argument rule
        (FR-PE-04) can never fire, so a model-composed argument is indistinguishable
        from a user-supplied one.
        """
        arguments = arguments or {}
        body = self.request("POST", "/v1/mediate/tool-call", {
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "argument_trust_labels": argument_trust_labels or {},
            "agent_id": agent_id or self.agent_id,
            "is_irreversible": is_irreversible,
            "is_high_impact": is_high_impact,
        }, fail_open=fail_open)
        return MediationResult.from_decision(body)

    def mediate_output(
        self,
        session_id: str,
        content: str,
        destination: str = "user",
        *,
        data_class_labels: list[str] | None = None,
        fail_open: bool = False,
    ) -> MediationResult:
        """
        Redact and authorise an outbound response (FR-OR-01/02).

        ``result.content`` is the safe text to send. Substituting it is the
        enforcement step — reading the verdict and sending the original anyway
        enforces nothing.
        """
        body = self.request("POST", "/v1/mediate/output", {
            "session_id": session_id,
            "content": content,
            "destination": destination,
            "data_class_labels": data_class_labels or [],
        }, fail_open=fail_open)
        return MediationResult.from_output(body)

    def mediate_memory_write(
        self,
        session_id: str,
        content: str,
        *,
        source: str = "agent",
        source_uri: str = "",
        trust_label: str = "untrusted_data",
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        fail_open: bool = False,
    ) -> MediationResult:
        """Vet a candidate memory write (FR-MI-01)."""
        body = self.request("POST", "/v1/mediate/memory/write", {
            "session_id": session_id,
            "content": content,
            "source": source,
            "source_uri": source_uri,
            "trust_label": trust_label,
            "agent_id": agent_id or self.agent_id,
            "metadata": metadata or {},
        }, fail_open=fail_open)
        return MediationResult.from_memory_write(body)

    def mediate_memory_read(
        self,
        session_id: str,
        memory_id: str,
        *,
        agent_id: str | None = None,
        rescan: bool = False,
        fail_open: bool = False,
    ) -> MediationResult:
        """Verify a memory record before the agent acts on it (FR-MI-02)."""
        body = self.request("POST", "/v1/mediate/memory/read", {
            "session_id": session_id,
            "memory_id": memory_id,
            "agent_id": agent_id or self.agent_id,
            "rescan": rescan,
        }, fail_open=fail_open)
        return MediationResult.from_memory_read(body)

    # -- audit --------------------------------------------------------------

    def replay_session(self, session_id: str, *, fail_open: bool = False) -> dict[str, Any]:
        """Return the full decision trail for a session (FR-AL-01)."""
        return self.request(
            "GET", f"/v1/audit/replay/{session_id}", None, fail_open=fail_open
        )

    def health(self, *, fail_open: bool = True) -> dict[str, Any]:
        """Liveness probe. Fails open by default — it is not a decision point."""
        return self.request("GET", "/health", None, fail_open=fail_open)


class AsyncSCMLClient(_BaseClient):
    """
    Asynchronous SCML client. Same surface as :class:`SCMLClient`.

    Holds no connection pool of its own by default so it is safe to construct
    per request; pass an ``httpx.AsyncClient`` as ``transport`` to reuse one.
    """

    def __init__(
        self,
        url: str = DEFAULT_API_URL,
        api_key: str | None = None,
        *,
        agent_id: str = "default",
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(url, api_key, agent_id=agent_id, timeout=timeout)
        self._transport = transport

    async def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        fail_open: bool = False,
    ) -> dict[str, Any]:
        """Low-level escape hatch: returns the raw JSON body."""
        try:
            if self._transport is not None:
                r = await self._transport.request(
                    method, f"{self.url}{path}", json=payload,
                    headers=self._headers, timeout=self.timeout,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    r = await c.request(
                        method, f"{self.url}{path}", json=payload, headers=self._headers,
                    )
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return self._on_transport_error(exc, path, fail_open)

    async def mediate_context(
        self,
        session_id: str,
        content: str,
        source: str = "tool_result",
        *,
        source_uri: str = "",
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        fail_open: bool = False,
    ) -> MediationResult:
        """Label and scan inbound content before an agent reads it (FR-IG-01)."""
        body = await self.request("POST", "/v1/mediate/context", {
            "session_id": session_id,
            "content": content,
            "source": source,
            "source_uri": source_uri,
            "agent_id": agent_id or self.agent_id,
            "metadata": metadata or {},
        }, fail_open=fail_open)
        return MediationResult.from_decision(body)

    async def mediate_tool_call(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        argument_trust_labels: dict[str, str] | None = None,
        agent_id: str | None = None,
        is_irreversible: bool = False,
        is_high_impact: bool = False,
        fail_open: bool = False,
    ) -> MediationResult:
        """Authorise a proposed tool call (FR-PE-01..04)."""
        body = await self.request("POST", "/v1/mediate/tool-call", {
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments": arguments or {},
            "argument_trust_labels": argument_trust_labels or {},
            "agent_id": agent_id or self.agent_id,
            "is_irreversible": is_irreversible,
            "is_high_impact": is_high_impact,
        }, fail_open=fail_open)
        return MediationResult.from_decision(body)

    async def mediate_output(
        self,
        session_id: str,
        content: str,
        destination: str = "user",
        *,
        data_class_labels: list[str] | None = None,
        fail_open: bool = False,
    ) -> MediationResult:
        """Redact and authorise an outbound response (FR-OR-01/02)."""
        body = await self.request("POST", "/v1/mediate/output", {
            "session_id": session_id,
            "content": content,
            "destination": destination,
            "data_class_labels": data_class_labels or [],
        }, fail_open=fail_open)
        return MediationResult.from_output(body)

    async def mediate_memory_write(
        self,
        session_id: str,
        content: str,
        *,
        source: str = "agent",
        source_uri: str = "",
        trust_label: str = "untrusted_data",
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        fail_open: bool = False,
    ) -> MediationResult:
        """Vet a candidate memory write (FR-MI-01)."""
        body = await self.request("POST", "/v1/mediate/memory/write", {
            "session_id": session_id,
            "content": content,
            "source": source,
            "source_uri": source_uri,
            "trust_label": trust_label,
            "agent_id": agent_id or self.agent_id,
            "metadata": metadata or {},
        }, fail_open=fail_open)
        return MediationResult.from_memory_write(body)

    async def mediate_memory_read(
        self,
        session_id: str,
        memory_id: str,
        *,
        agent_id: str | None = None,
        rescan: bool = False,
        fail_open: bool = False,
    ) -> MediationResult:
        """Verify a memory record before the agent acts on it (FR-MI-02)."""
        body = await self.request("POST", "/v1/mediate/memory/read", {
            "session_id": session_id,
            "memory_id": memory_id,
            "agent_id": agent_id or self.agent_id,
            "rescan": rescan,
        }, fail_open=fail_open)
        return MediationResult.from_memory_read(body)

    async def replay_session(
        self, session_id: str, *, fail_open: bool = False
    ) -> dict[str, Any]:
        """Return the full decision trail for a session (FR-AL-01)."""
        return await self.request(
            "GET", f"/v1/audit/replay/{session_id}", None, fail_open=fail_open
        )

    async def health(self, *, fail_open: bool = True) -> dict[str, Any]:
        """Liveness probe. Fails open by default — it is not a decision point."""
        return await self.request("GET", "/health", None, fail_open=fail_open)


# Product name is SCML; the engine is TrustMediator. Both names are real and
# both are supported, so existing call sites keep working.
TrustMediatorClient = SCMLClient
AsyncTrustMediatorClient = AsyncSCMLClient
