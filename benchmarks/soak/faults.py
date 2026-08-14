"""
Fault injectors (PRD §8.3).

Each fault breaks one dependency of the live pipeline the way it would break in
production — a model server that stops answering, a database that refuses
connections, a policy store that times out. Faults are applied to a real
`MediationPipeline` and reverted cleanly, so a soak can alternate healthy and
degraded windows against one long-lived instance.

Nothing here is test-only scaffolding inside `trust_mediator/`: the production
objects are patched from outside, so what runs during a fault window is the
same code that runs in production.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable


class InjectedFault(RuntimeError):
    """Raised by a broken dependency. Distinguishable from a real defect."""


@dataclass
class Fault:
    """One named failure mode that can be applied to and reverted from a pipeline."""

    name: str
    description: str
    #: PRD §9 row this exercises — what the mediator is required to do.
    expected: str
    _apply: Callable[[Any], list[tuple[Any, str, Any]]]

    def apply(self, pipeline: Any) -> "AppliedFault":
        return AppliedFault(self, self._apply(pipeline))


@dataclass
class AppliedFault:
    """Handle for reverting a fault. Restores the exact original attributes."""

    fault: Fault
    _saved: list[tuple[Any, str, Any]]

    def revert(self) -> None:
        for obj, attr, original in self._saved:
            setattr(obj, attr, original)


def _patch(obj: Any, attr: str, replacement: Any) -> tuple[Any, str, Any]:
    original = getattr(obj, attr)
    setattr(obj, attr, replacement)
    return (obj, attr, original)


def _raiser(message: str) -> Callable[..., Any]:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise InjectedFault(message)
    return _boom


def _async_raiser(message: str) -> Callable[..., Any]:
    async def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise InjectedFault(message)
    return _boom


def _slow(delay_s: float, inner: Callable[..., Any]) -> Callable[..., Any]:
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        import time
        time.sleep(delay_s)          # deliberately blocking: models are CPU-bound
        return inner(*args, **kwargs)
    return _wrapped


# ── Fault definitions ─────────────────────────────────────────────────────────

SCANNER_DOWN = Fault(
    name="scanner_down",
    description="Model server unreachable — the injection classifier raises",
    expected="low-risk reads fail open and are tagged; risky_external escalates",
    _apply=lambda p: [
        _patch(p._scanner._classifier, "predict", _raiser("model server unreachable")),
        _patch(p._scanner._filter, "scan", _raiser("model server unreachable")),
    ],
)

POLICY_STORE_DOWN = Fault(
    name="policy_store_down",
    description="Policy store unreachable — tool calls cannot be authorised",
    expected="fail closed: every tool call denied with mediator_error",
    _apply=lambda p: [
        _patch(p._policy_engine._loader, "get_policy", _async_raiser("policy store down")),
    ],
)

MEMORY_STORE_DOWN = Fault(
    name="memory_store_down",
    description="Memory database unreachable — existing memory cannot be read",
    expected="fail closed: candidate writes quarantined, never persisted active",
    _apply=lambda p: [
        _patch(p._memory._repo, "list_active", _async_raiser("memory db down")),
        _patch(p._memory._repo, "save", _async_raiser("memory db down")),
    ],
)

REDACTOR_DOWN = Fault(
    name="redactor_down",
    description="Redaction engine failure on the egress path",
    expected="fail closed: outbound response blocked, nothing released",
    _apply=lambda p: [
        _patch(p._redactor, "redact", _raiser("redactor unavailable")),
    ],
)

AUDIT_STORE_DOWN = Fault(
    name="audit_store_down",
    description="Audit database unreachable — decisions cannot be persisted",
    expected="mediation continues; audit loss is recorded, not fatal (§8.3)",
    _apply=lambda p: [
        _patch(p._audit._repo, "append_chained", _async_raiser("audit db down")),
        _patch(p._audit._repo, "append_chained_batch", _async_raiser("audit db down")),
    ],
)

SCANNER_SLOW = Fault(
    name="scanner_slow",
    description="Model server degraded — each scan takes 250ms",
    expected="decisions still rendered; latency degrades, availability does not",
    _apply=lambda p: [
        _patch(p._scanner._filter, "scan", _slow(0.25, p._scanner._filter.scan)),
    ],
)

ALL_FAULTS: list[Fault] = [
    SCANNER_DOWN,
    POLICY_STORE_DOWN,
    MEMORY_STORE_DOWN,
    REDACTOR_DOWN,
    AUDIT_STORE_DOWN,
    SCANNER_SLOW,
]


def get_fault(name: str) -> Fault:
    for fault in ALL_FAULTS:
        if fault.name == name:
            return fault
    raise SystemExit(
        f"Unknown fault {name!r}. Available: " + ", ".join(f.name for f in ALL_FAULTS)
    )


async def hold(seconds: float) -> None:
    """Sleep without blocking the driver's event loop."""
    await asyncio.sleep(seconds)
