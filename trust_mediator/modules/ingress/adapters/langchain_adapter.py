"""
LangChain adapter — transparently wraps LangChain retrievers and tools
so they route through TrustMediator (FR-IG-02).

Usage:
    from trust_mediator.modules.ingress.adapters.langchain_adapter import (
        MediatedRetriever, MediatedTool
    )
    safe_retriever = MediatedRetriever(retriever, interceptor, pipeline)
    safe_tool = MediatedTool(tool, interceptor, pipeline)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from trust_mediator.core.pipeline import MediationPipeline
    from trust_mediator.modules.ingress.interceptor import IngressInterceptor


class MediatedRetriever:
    """
    Wraps a LangChain-compatible retriever so every retrieved chunk is
    intercepted, trust-labelled, and scanned before the agent sees it.
    """

    def __init__(
        self,
        retriever: Any,
        interceptor: "IngressInterceptor",
        pipeline: "MediationPipeline",
    ) -> None:
        self._retriever = retriever
        self._interceptor = interceptor
        self._pipeline = pipeline

    async def ainvoke(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Async retrieval with mediation."""
        raw_docs = await self._retriever.ainvoke(query, **kwargs)
        mediated = []
        for i, doc in enumerate(raw_docs):
            content = doc.page_content if hasattr(doc, "page_content") else str(doc)
            source_uri = doc.metadata.get("source", f"retrieval:{i}") if hasattr(doc, "metadata") else f"retrieval:{i}"
            envelope = self._interceptor.wrap_retrieval(
                content,
                source_uri=source_uri,
                chunk_index=i,
            )
            result_envelope = await self._pipeline.process_context(envelope)
            mediated.append({
                "content": result_envelope.content,
                "trust_label": result_envelope.trust_label.value,
                "scanner_verdict": result_envelope.scanner_verdict.decision.value,
                "envelope_id": result_envelope.id,
                "original_metadata": doc.metadata if hasattr(doc, "metadata") else {},
            })
        return mediated

    def invoke(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Sync retrieval — wraps async in a new event loop (dev use only)."""
        import asyncio
        return asyncio.run(self.ainvoke(query, **kwargs))


class MediatedTool:
    """
    Wraps a LangChain-compatible tool so every invocation is policy-checked
    and every result is trust-labelled.
    """

    def __init__(
        self,
        tool: Any,
        interceptor: "IngressInterceptor",
        pipeline: "MediationPipeline",
    ) -> None:
        self._tool = tool
        self._interceptor = interceptor
        self._pipeline = pipeline
        self.name: str = getattr(tool, "name", "unknown_tool")
        self.description: str = getattr(tool, "description", "")

    async def arun(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Async tool run with policy gate + result mediation."""
        from trust_mediator.models.tool_call import ToolCallRequest
        arguments = {"args": args, **kwargs}
        tool_call = ToolCallRequest(
            session_id=self._interceptor.session_id,
            tool_name=self.name,
            arguments=arguments,
            agent_id=self._interceptor.agent_id,
        )
        policy_result = await self._pipeline.process_tool_call(tool_call)
        if not policy_result.is_allowed:
            return {
                "blocked": True,
                "reason": policy_result.reason,
                "reason_code": policy_result.reason_code.value,
            }
        # Execute the tool
        if hasattr(self._tool, "arun"):
            raw_result = await self._tool.arun(*args, **kwargs)
        else:
            raw_result = self._tool.run(*args, **kwargs)

        # Wrap result
        envelope = self._interceptor.wrap_tool_result(
            raw_result,
            tool_name=self.name,
        )
        mediated = await self._pipeline.process_context(envelope)
        return {
            "content": mediated.content,
            "trust_label": mediated.trust_label.value,
            "scanner_verdict": mediated.scanner_verdict.decision.value,
            "envelope_id": mediated.id,
        }
