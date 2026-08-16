"""
SCML — Secure Context Mediation Layer.

SCML is the product; ``trust_mediator`` is the engine package that implements
it. This module is a thin alias so that installing and importing match the
product name::

    from scml import SCMLClient

Every name here is re-exported from :mod:`trust_mediator` and the two are
interchangeable — there is no second implementation to drift. See that
module's docstring for the public API contract.

``__all__`` is written out literally rather than copied from the engine at
import time so that linters and IDEs can see it. ``test_public_api.py``
asserts the two lists stay identical.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import trust_mediator as _engine
from trust_mediator import (
    AsyncSCMLClient,
    AsyncTrustMediatorClient,
    MediationResult,
    SCMLBlocked,
    SCMLClient,
    SCMLError,
    SCMLUnavailable,
    TrustLabel,
    TrustMediatorClient,
    Verdict,
    __version__,
    classify_decision,
)

if TYPE_CHECKING:
    from trust_mediator import MediationPipeline, settings


def __getattr__(name: str) -> Any:
    """
    Delegate anything not eagerly re-exported to the engine package.

    This is what keeps the lazy names (``MediationPipeline``, ``settings``)
    lazy: re-exporting them eagerly here would import the server stack and
    defeat the point of a client-only install.
    """
    if name.startswith("_"):
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        return getattr(_engine, name)
    except AttributeError:
        # Report against this module, not the engine — an alias that blames a
        # package the caller never imported is a confusing traceback.
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None


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
