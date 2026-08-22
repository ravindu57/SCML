"""
AgentDojo testbed (PRD §14.1) — external validation on a *dynamic* benchmark.

Unlike the InjecAgent corpus, AgentDojo executes a live agent: it needs an LLM,
it costs requests, and its results are not bit-reproducible. Only the Gemini
compatibility shim exists so far; the testbed itself is not built.

Not exported from `benchmarks.testbeds` by default because running it requires
the `agentdojo` package, which is deliberately not a dependency of this repo.
"""

from benchmarks.testbeds.agentdojo.gemini_compat import (
    GEMINI_OPENAI_BASE_URL,
    GeminiToolLoopClient,
    wrap_for_gemini,
)

__all__ = ["GEMINI_OPENAI_BASE_URL", "GeminiToolLoopClient", "wrap_for_gemini"]
