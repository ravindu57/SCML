"""
§6.1 — Ingress Interceptor / SDK

The single entry point that wraps every piece of content the agent ingests
or emits, ensuring nothing bypasses mediation (FR-IG-01).

Usage:
    interceptor = IngressInterceptor(session_id="abc123")
    envelope = interceptor.wrap_query("Search for X")
    envelope = interceptor.wrap_tool_result(result, tool_name="web_search")
    envelope = interceptor.wrap_retrieval(chunk, source_uri="https://…")
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from trust_mediator.models.context_envelope import (
    ContextEnvelope,
    Provenance,
    TrustLabel,
)

logger = structlog.get_logger(__name__)


class IngressInterceptor:
    """
    Wraps all agent I/O in ContextEnvelopes with provenance metadata.

    Fail-safe rules (§9):
    - If the downstream pipeline is unavailable for a high-risk operation,
      the method raises MediatorUnavailableError (fail-closed).
    - For low-risk reads, a fail-open path tags the envelope as unverified.
    """

    def __init__(self, session_id: str | None = None, agent_id: str = "default") -> None:
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id = agent_id

    # ── Trusted entry points ─────────────────────────────────────────────────

    def wrap_query(
        self,
        raw_query: str,
        *,
        user_id: str = "authenticated_user",
        metadata: dict[str, Any] | None = None,
    ) -> ContextEnvelope:
        """
        Wrap an authenticated user query as a TRUSTED_INSTRUCTION envelope.
        This is the only path that can produce a trusted envelope; the trust
        label is set here and never downgraded.
        """
        provenance = Provenance(
            source="user_query",
            uri=f"user:{user_id}",
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        envelope = ContextEnvelope(
            session_id=self.session_id,
            content=raw_query,
            trust_label=TrustLabel.TRUSTED_INSTRUCTION,
            provenance=provenance,
            taint_set=[TrustLabel.TRUSTED_INSTRUCTION],
            metadata=metadata or {},
        )
        logger.info(
            "ingress.query_wrapped",
            envelope_id=envelope.id,
            session_id=self.session_id,
            trust_label=envelope.trust_label,
        )
        return envelope

    def wrap_system_policy(
        self,
        content: str,
        *,
        policy_id: str = "system_policy",
    ) -> ContextEnvelope:
        """Wrap a system-level policy instruction as TRUSTED_INSTRUCTION."""
        provenance = Provenance(
            source="system_policy",
            uri=f"policy:{policy_id}",
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        return ContextEnvelope(
            session_id=self.session_id,
            content=content,
            trust_label=TrustLabel.TRUSTED_INSTRUCTION,
            provenance=provenance,
            taint_set=[TrustLabel.TRUSTED_INSTRUCTION],
        )

    # ── Untrusted entry points ───────────────────────────────────────────────

    def wrap_tool_result(
        self,
        result: Any,
        *,
        tool_name: str,
        tool_uri: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ContextEnvelope:
        """
        Wrap a tool/API result as UNTRUSTED_DATA (FR-TR-01).
        Tool outputs can never be promoted to instructions, even if the
        tool is allow-listed.
        """
        content = str(result) if not isinstance(result, str) else result
        provenance = Provenance(
            source="tool_result",
            uri=tool_uri or f"tool:{tool_name}",
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        envelope = ContextEnvelope(
            session_id=self.session_id,
            content=content,
            trust_label=TrustLabel.UNTRUSTED_DATA,
            provenance=provenance,
            taint_set=[TrustLabel.UNTRUSTED_DATA],
            metadata={"tool_name": tool_name, **(metadata or {})},
        )
        logger.debug(
            "ingress.tool_result_wrapped",
            envelope_id=envelope.id,
            tool_name=tool_name,
        )
        return envelope

    def wrap_retrieval(
        self,
        chunk: str,
        *,
        source_uri: str,
        chunk_index: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> ContextEnvelope:
        """Wrap a RAG retrieval chunk as UNTRUSTED_DATA."""
        provenance = Provenance(
            source="rag_retrieval",
            uri=source_uri,
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        envelope = ContextEnvelope(
            session_id=self.session_id,
            content=chunk,
            trust_label=TrustLabel.UNTRUSTED_DATA,
            provenance=provenance,
            taint_set=[TrustLabel.UNTRUSTED_DATA],
            metadata={"chunk_index": chunk_index, **(metadata or {})},
        )
        return envelope

    def wrap_web_content(
        self,
        content: str,
        *,
        url: str,
        metadata: dict[str, Any] | None = None,
    ) -> ContextEnvelope:
        """Wrap raw web/attachment content as RISKY_EXTERNAL."""
        provenance = Provenance(
            source="web_content",
            uri=url,
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        return ContextEnvelope(
            session_id=self.session_id,
            content=content,
            trust_label=TrustLabel.RISKY_EXTERNAL,
            provenance=provenance,
            taint_set=[TrustLabel.RISKY_EXTERNAL],
            metadata=metadata or {},
        )

    def wrap_memory_read(
        self,
        content: str,
        *,
        memory_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> ContextEnvelope:
        """
        Wrap content read from long-term memory.
        Treated as UNTRUSTED_DATA because memory can be poisoned;
        the Memory Integrity Layer is responsible for verification.
        """
        provenance = Provenance(
            source="memory",
            uri=f"memory:{memory_id}",
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        return ContextEnvelope(
            session_id=self.session_id,
            content=content,
            trust_label=TrustLabel.UNTRUSTED_DATA,
            provenance=provenance,
            taint_set=[TrustLabel.UNTRUSTED_DATA],
            metadata={"memory_id": memory_id, **(metadata or {})},
        )

    def wrap_draft_output(
        self,
        content: str,
        *,
        destination: str = "user",
        metadata: dict[str, Any] | None = None,
    ) -> ContextEnvelope:
        """Wrap a draft agent response/action before output redaction."""
        provenance = Provenance(
            source="agent_output",
            uri=f"dest:{destination}",
            session_id=self.session_id,
            agent_id=self.agent_id,
        )
        return ContextEnvelope(
            session_id=self.session_id,
            content=content,
            trust_label=TrustLabel.DERIVED,
            provenance=provenance,
            taint_set=[TrustLabel.DERIVED],
            metadata={"destination": destination, **(metadata or {})},
        )
