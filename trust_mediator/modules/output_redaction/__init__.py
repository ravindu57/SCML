"""Output redaction package.

``SanitizationResult`` and ``ToolOutputSanitizer`` are core-safe (the SDK's
``client.sanitize_tool_output`` reaches them) and are imported eagerly.
``OutputRedactor`` lives in ``redactor.py``, which imports structlog — a
[server] dependency — so it is resolved lazily on first access, mirroring how
the top-level package handles ``MediationPipeline``/``settings``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from trust_mediator.modules.output_redaction.sanitizer import (
    SanitizationResult,
    ToolOutputSanitizer,
)

_LAZY: dict[str, tuple[str, str]] = {
    "OutputRedactor": (
        "trust_mediator.modules.output_redaction.redactor",
        "OutputRedactor",
    ),
}

if TYPE_CHECKING:  # so type checkers and IDEs still see the lazy name
    from trust_mediator.modules.output_redaction.redactor import OutputRedactor


def __getattr__(name: str) -> Any:
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


__all__ = ["OutputRedactor", "SanitizationResult", "ToolOutputSanitizer"]