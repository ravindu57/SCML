"""
PRD §14.1 — the Gemini shim must round-trip `thought_signature`.

Gemini 3.x rejects a replayed tool call that arrives without the signature it
issued, and AgentDojo replays the whole exchange every turn. Measured against
the live API: every Gemini 3.x model (3.1/3.5/3.6, flash and flash-lite) fails
identically on turn two, so this is a serialisation gap rather than something
a different model choice avoids.

These tests use stub clients rather than the real SDK: the shim deliberately
imports neither `openai` nor `agentdojo`, so it stays testable in the SCML
virtualenv where neither is installed.
"""
from __future__ import annotations

from typing import Any

from benchmarks.testbeds.agentdojo import wrap_for_gemini

SIGNATURE = {"google": {"thought_signature": "ErEDCq4DARFNMg83slnV7xTM"}}


class _Completions:
    """Records what it was asked to send, and replies with a scripted response."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self._responses.pop(0)

    @property
    def last_messages(self) -> list[Any]:
        return self.calls[-1]["messages"]


class _Chat:
    def __init__(self, responses: list[Any]) -> None:
        self.completions = _Completions(responses)


class _Client:
    def __init__(self, responses: list[Any]) -> None:
        self.chat = _Chat(responses)
        self.api_key = "sentinel"


def _response(call_id: str, *, with_signature: bool = True) -> dict[str, Any]:
    call: dict[str, Any] = {
        "id": call_id,
        "type": "function",
        "function": {"name": "get_current_day", "arguments": "{}"},
    }
    if with_signature:
        call["extra_content"] = SIGNATURE
    return {"choices": [{"message": {"role": "assistant", "tool_calls": [call]}}]}


def _replayed_history(call_id: str) -> list[dict[str, Any]]:
    """History as AgentDojo rebuilds it — the signature already stripped."""
    return [
        {"role": "user", "content": "What day is it?"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": "get_current_day", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": call_id, "content": "2026-08-22"},
    ]


class TestSignatureRoundTrip:
    def test_signature_is_restored_on_the_replayed_tool_call(self):
        """The failure this exists to prevent: turn two rejected 400."""
        inner = _Client([_response("call_1"), _response("call_2")])
        client = wrap_for_gemini(inner)

        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        client.chat.completions.create(model="m", messages=_replayed_history("call_1"))

        sent = inner.chat.completions.last_messages
        assistant = next(m for m in sent if m["role"] == "assistant")
        assert assistant["tool_calls"][0]["extra_content"] == SIGNATURE

    def test_unknown_tool_calls_are_left_alone(self):
        """A call id the shim never saw must not acquire someone else's
        signature — that would be forging provenance, not restoring it."""
        inner = _Client([_response("call_1"), _response("call_2")])
        client = wrap_for_gemini(inner)

        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        client.chat.completions.create(model="m", messages=_replayed_history("call_UNSEEN"))

        assistant = next(
            m for m in inner.chat.completions.last_messages if m["role"] == "assistant"
        )
        assert "extra_content" not in assistant["tool_calls"][0]

    def test_an_existing_signature_is_not_overwritten(self):
        inner = _Client([_response("call_1"), _response("call_2")])
        client = wrap_for_gemini(inner)
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])

        history = _replayed_history("call_1")
        mine = {"google": {"thought_signature": "CALLER_SUPPLIED"}}
        next(m for m in history if m["role"] == "assistant")["tool_calls"][0]["extra_content"] = mine

        client.chat.completions.create(model="m", messages=history)
        assistant = next(
            m for m in inner.chat.completions.last_messages if m["role"] == "assistant"
        )
        assert assistant["tool_calls"][0]["extra_content"] == mine

    def test_the_callers_history_is_not_mutated(self):
        """AgentDojo owns that transcript and it is the evidence being
        measured; rewriting it in place would corrupt the record."""
        inner = _Client([_response("call_1"), _response("call_2")])
        client = wrap_for_gemini(inner)
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])

        history = _replayed_history("call_1")
        client.chat.completions.create(model="m", messages=history)

        original = next(m for m in history if m["role"] == "assistant")
        assert "extra_content" not in original["tool_calls"][0]


class TestPassThrough:
    def test_a_response_without_signatures_stores_nothing(self):
        """Models that do not emit signatures must not gain empty ones."""
        inner = _Client([_response("call_1", with_signature=False)])
        client = wrap_for_gemini(inner)
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        assert client.signatures_seen == 0

    def test_messages_without_tool_calls_are_untouched(self):
        inner = _Client([_response("call_1"), _response("call_2")])
        client = wrap_for_gemini(inner)
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])

        plain = [{"role": "user", "content": "again"}]
        client.chat.completions.create(model="m", messages=plain)
        assert inner.chat.completions.last_messages == plain

    def test_other_client_attributes_delegate(self):
        """It is a drop-in: anything not overridden reaches the real client."""
        client = wrap_for_gemini(_Client([_response("call_1")]))
        assert client.api_key == "sentinel"

    def test_signatures_seen_counts_captures(self):
        inner = _Client([_response("call_1"), _response("call_2")])
        client = wrap_for_gemini(inner)
        client.chat.completions.create(model="m", messages=[])
        client.chat.completions.create(model="m", messages=[])
        assert client.signatures_seen == 2
