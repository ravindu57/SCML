"""
Round-trip Gemini's ``thought_signature`` through an OpenAI-shaped tool loop.

AgentDojo drives a multi-turn agent: the assistant emits a tool call, the
harness runs it, and the whole exchange is replayed as history on the next
request. Gemini 3.x rejects that replay unless each ``functionCall`` carries
back the ``thought_signature`` it issued::

    400 INVALID_ARGUMENT — Function call is missing a thought_signature in
    functionCall parts. This is required for tools to work correctly.

The signature *is* returned, on the tool call rather than the message::

    tool_call.extra_content.google.thought_signature

but the OpenAI chat-completions schema has no field for it, so AgentDojo —
which rebuilds requests from its own ``FunctionCall`` type (``function``,
``args``, ``id``, ``placeholder_args``) — drops it. Every Gemini 3.x model
fails identically on turn two, flash and flash-lite alike; it is a
serialisation gap, not a model capability.

``FunctionCall`` is a pydantic model with ``extra="ignore"``, so the signature
cannot be smuggled on it. Instead this keeps a side table keyed by tool-call
id, which is the one identifier that survives the conversion intact.

Wrapping the *client* rather than subclassing ``OpenAILLM`` is deliberate:
AgentDojo only ever calls ``chat.completions.create``, so the fix needs no
knowledge of AgentDojo's internals, survives upgrading the package, and is
deleted rather than migrated when the model moves to one that does not need it.

Nothing here imports ``openai`` or ``agentdojo``: it wraps any object exposing
``chat.completions.create``, which keeps it testable in the SCML virtualenv,
where neither is installed.

Usage (in the benchmark virtualenv)::

    client = wrap_for_gemini(openai.OpenAI(api_key=key, base_url=GEMINI_OPENAI_BASE_URL))
    llm = OpenAILLM(client, "gemini-3.6-flash")
"""
from __future__ import annotations

from typing import Any

#: Gemini's OpenAI-compatible endpoint.
GEMINI_OPENAI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"

#: Where Gemini returns the signature on a tool call.
_EXTRA = "extra_content"


def _get(obj: Any, name: str) -> Any:
    """Read a field from a dict or a pydantic/attr object, or None."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _as_dict(obj: Any) -> dict[str, Any] | None:
    """Best-effort plain-dict view, without requiring pydantic."""
    if isinstance(obj, dict):
        return obj
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return dump(exclude_none=True)
        except Exception:  # noqa: BLE001 — a dump failure must not break the call
            return None
    return None


class _SignatureStore:
    """Remembers the ``extra_content`` Gemini attached to each tool call."""

    def __init__(self) -> None:
        self._by_id: dict[str, Any] = {}

    def __len__(self) -> int:
        return len(self._by_id)

    def capture(self, response: Any) -> None:
        """Record signatures from a completion response."""
        for choice in _get(response, "choices") or []:
            message = _get(choice, "message")
            for call in _get(message, "tool_calls") or []:
                call_id = _get(call, "id")
                extra = _get(call, _EXTRA)
                # Pydantic parks unmodelled fields on model_extra; the OpenAI
                # SDK has no extra_content field, so that is where it lands.
                if extra is None:
                    extra = (getattr(call, "model_extra", None) or {}).get(_EXTRA)
                if extra is None:
                    dumped = _as_dict(call)
                    extra = dumped.get(_EXTRA) if dumped else None
                if call_id and extra is not None:
                    self._by_id[call_id] = extra

    def reattach(self, messages: Any) -> Any:
        """Return ``messages`` with known signatures restored on tool calls.

        Copies rather than mutating: the caller's history is AgentDojo's, and a
        benchmark that silently rewrites the transcript it is measuring would
        be unusable as evidence.
        """
        if not self._by_id or not isinstance(messages, list):
            return messages

        out: list[Any] = []
        for message in messages:
            out.append(self._restore_message(message))
        return out

    def _restore_message(self, message: Any) -> Any:
        calls = _get(message, "tool_calls")
        if not calls:
            return message

        as_dict = _as_dict(message)
        if as_dict is None:
            return message

        restored = dict(as_dict)
        new_calls = []
        changed = False
        for call in restored.get("tool_calls") or []:
            call_dict = _as_dict(call)
            if call_dict is None:
                new_calls.append(call)
                continue
            call_copy = dict(call_dict)
            extra = self._by_id.get(call_copy.get("id"))
            if extra is not None and _EXTRA not in call_copy:
                call_copy[_EXTRA] = extra
                changed = True
            new_calls.append(call_copy)

        if not changed:
            return message
        restored["tool_calls"] = new_calls
        return restored


class _Completions:
    def __init__(self, inner: Any, store: _SignatureStore) -> None:
        self._inner = inner
        self._store = store

    def create(self, *args: Any, **kwargs: Any) -> Any:
        if "messages" in kwargs:
            kwargs["messages"] = self._store.reattach(kwargs["messages"])
        response = self._inner.create(*args, **kwargs)
        self._store.capture(response)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _Chat:
    def __init__(self, inner: Any, store: _SignatureStore) -> None:
        self._inner = inner
        self.completions = _Completions(inner.completions, store)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class GeminiToolLoopClient:
    """An OpenAI-shaped client that preserves Gemini thought signatures.

    Delegates everything it does not override, so it is a drop-in for whatever
    the caller passes in.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._store = _SignatureStore()
        self.chat = _Chat(inner.chat, self._store)

    @property
    def signatures_seen(self) -> int:
        """How many tool calls have a stored signature — 0 after a run means
        the shim did nothing, which is worth failing a benchmark over."""
        return len(self._store)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def wrap_for_gemini(client: Any) -> GeminiToolLoopClient:
    """Wrap an OpenAI-compatible client for Gemini's tool loop."""
    return GeminiToolLoopClient(client)
