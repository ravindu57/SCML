"""
TrustMediator — Trust-Aware Context Mediation Middleware
=========================================================
A lightweight, framework-agnostic security layer that sits between an LLM agent
and everything it reads or acts on. Provides:

  • Trust classification and taint propagation
  • Injection scanning (heuristic + pluggable classifier)
  • Least-agency tool-call policy enforcement
  • Memory write integrity vetting (primary contribution)
  • Output redaction and exfiltration prevention
  • Append-only tamper-evident audit logging

SCML is the product name; TrustMediator is the engine. ``import scml`` and
``import trust_mediator`` expose the same public API.

Public API — this is what semantic versioning protects
------------------------------------------------------
Everything listed in ``__all__`` below is supported and will not change
incompatibly without a major version bump. **Everything else is internal**:
``trust_mediator.modules.*``, ``trust_mediator.db.*``, ``trust_mediator.api.*``
and any name with a leading underscore may change in any release. If you need
something from those, open an issue rather than importing it — being explicit
about the boundary is what lets the engine keep moving.

Typical use — an agent calling a mediator over HTTP::

    from trust_mediator import SCMLClient

    scml = SCMLClient("http://localhost:8000", api_key="sk-...")
    ctx = scml.mediate_context(session_id="s1", content=supplier_doc)
    decision = scml.mediate_tool_call(
        session_id="s1",
        tool_name="release_container",
        arguments={"container_id": cid},
        argument_trust_labels={"container_id": ctx.trust_label},
    )
    if not decision.allowed:
        raise RuntimeError(decision.reason)

``MediationPipeline`` (the in-process path, no HTTP hop) and ``settings`` are
resolved lazily so that a client-only install — which has neither a database
driver nor a web server — can import this package in about a second.

PRD Reference: TrustMediator PRD v1.0 (16 July 2026)
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

# Single source of truth for the version. pyproject.toml reads this attribute
# (see [tool.setuptools.dynamic]), so it must stay a plain literal assignment
# that setuptools can parse without importing the package.
__version__ = "1.0.0"
__author__ = "TrustMediator Project"

# The client SDK is the core install and depends only on httpx + pydantic, so
# it is safe to import eagerly. The models are pure pydantic for the same
# reason.
from trust_mediator.client import (
    AsyncSCMLClient,
    AsyncTrustMediatorClient,
    MediationResult,
    SCMLBlocked,
    SCMLClient,
    SCMLError,
    SCMLUnavailable,
    TrustMediatorClient,
    Verdict,
    classify_decision,
)
from trust_mediator.models.context_envelope import TrustLabel

# Names resolved on first access: module path → attribute name. These pull in
# the [server]/[embedded] stack, which a client-only install does not have.
_LAZY: dict[str, tuple[str, str]] = {
    "MediationPipeline": ("trust_mediator.core.pipeline", "MediationPipeline"),
    "settings": ("trust_mediator.config", "settings"),
}

if TYPE_CHECKING:  # so type checkers and IDEs still see the lazy names
    from trust_mediator.config import settings
    from trust_mediator.core.pipeline import MediationPipeline


def __getattr__(name: str) -> Any:
    """Resolve the lazy names, with an actionable error if an extra is missing."""
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_path, attr = target
    try:
        module = __import__(module_path, fromlist=[attr])
    except ImportError as exc:
        raise ImportError(
            f"{name} requires the server stack, which is not installed. "
            f'Install it with:  pip install "trust-mediator[embedded]"  '
            f"(or [server] to run the mediator itself). Original error: {exc}"
        ) from exc
    value = getattr(module, attr)
    globals()[name] = value  # cache so subsequent lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(__all__)


__all__ = [
    # Clients
    "SCMLClient",
    "AsyncSCMLClient",
    "TrustMediatorClient",
    "AsyncTrustMediatorClient",
    # Results and verdicts
    "MediationResult",
    "Verdict",
    "classify_decision",
    "TrustLabel",
    # Exceptions
    "SCMLError",
    "SCMLBlocked",
    "SCMLUnavailable",
    # Lazy — require [embedded]/[server]
    "MediationPipeline",
    "settings",
    # Metadata
    "__version__",
]
