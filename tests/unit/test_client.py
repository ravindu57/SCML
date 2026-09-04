"""
Unit tests for the SCML client SDK (trust_mediator.client).

The client is the supported public interface, so these tests pin the two
things a consumer depends on and cannot verify for themselves:

  1. Verdict normalisation across five differently-shaped endpoint responses
     (FR-PE-01..04, FR-MI-01, FR-OR-01/02). A caller writes `if not
     result.allowed` once; it has to mean the same thing every time.
  2. Fail-closed transport behaviour (PRD §9). An unreachable mediator must
     never be indistinguishable from an allow.
"""
from __future__ import annotations

import httpx
import pytest

from trust_mediator.client import (
    AsyncSCMLClient,
    MediationResult,
    SCMLBlocked,
    SCMLClient,
    SCMLUnavailable,
    Verdict,
    classify_decision,
)


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200):
        self._payload = payload
        self.status_code = status
        self.text = str(payload)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> dict:
        return self._payload


@pytest.fixture
def stub_transport(monkeypatch):
    """Replace httpx.Client.request with a canned response; records the calls.

    Patches the bound method rather than ``httpx.request``: the sync client
    builds an ``httpx.Client`` so it can pass ``cert=`` for mTLS (NFR-SEC-03),
    which the module-level ``httpx.request`` does not accept. Constructing a
    real Client opens no connection, so only the request needs stubbing.
    """
    calls: list[dict] = []

    def _install(payload: dict, status: int = 200):
        def fake_request(self, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return _FakeResponse(payload, status)

        monkeypatch.setattr(httpx.Client, "request", fake_request)
        return calls

    return _install


# ── Verdict classification ────────────────────────────────────────────────────

class TestClassifyDecision:
    """The branch order here has caught real escapes; pin every case."""

    @pytest.mark.parametrize("raw", ["allow", "ALLOW", "persist", "transform"])
    def test_allow_synonyms_classify_as_allow(self, raw):
        assert classify_decision(raw) is Verdict.ALLOW

    @pytest.mark.parametrize("raw", ["block", "reject", "deny", "deny.schema_violation"])
    def test_deny_arrives_suffixed_and_still_blocks(self, raw):
        assert classify_decision(raw) is Verdict.BLOCK

    @pytest.mark.parametrize(
        "raw",
        [
            "require_approval",
            "require_approval.irreversible",
            "require_approval.high_impact",
            "require_approval.untrusted_arg",
        ],
    )
    def test_fr_pe_03_approval_gates_are_never_treated_as_allow(self, raw):
        """A gated call previously matched no branch and passed silently."""
        verdict = classify_decision(raw)
        assert verdict is Verdict.APPROVAL_REQUIRED
        assert not MediationResult(verdict=verdict, decision=raw).allowed

    def test_unrecognised_verdict_is_unknown_not_allow(self):
        assert classify_decision("something_new") is Verdict.UNKNOWN
        assert not MediationResult(
            verdict=Verdict.UNKNOWN, decision="something_new"
        ).allowed

    @pytest.mark.parametrize("raw", ["", None, "error"])
    def test_empty_or_error_is_error(self, raw):
        assert classify_decision(raw) is Verdict.ERROR


# ── Response-shape normalisation ──────────────────────────────────────────────

class TestResultNormalisation:
    """Five endpoints, three response shapes, one meaning of `allowed`."""

    def test_output_has_no_decision_key_and_must_not_read_as_allow(self):
        """
        /v1/mediate/output reports `blocked`, never `decision`. A caller
        branching on result["decision"] sees nothing and sends blocked content.
        """
        blocked = MediationResult.from_output(
            {"content": "", "blocked": True, "block_reason": "PII to external sink",
             "redactions_applied": [], "action_allowed": False}
        )
        assert blocked.verdict is Verdict.BLOCK
        assert not blocked.allowed
        assert blocked.reason == "PII to external sink"

    def test_output_allowed_returns_redacted_content_to_substitute(self):
        ok = MediationResult.from_output(
            {"content": "safe text", "blocked": False, "block_reason": "",
             "redactions_applied": [{"type": "email"}], "action_allowed": True}
        )
        assert ok.allowed
        assert ok.content == "safe text"

    def test_fr_mi_01_memory_write_uses_verdict_not_decision(self):
        persisted = MediationResult.from_memory_write(
            {"record_id": "m1", "verdict": "persist", "status": "active",
             "integrity_score": 0.9, "blocked": False, "quarantine_reason": ""}
        )
        assert persisted.allowed

    def test_quarantined_memory_write_is_not_allowed(self):
        """Quarantine stores the record but must not read as permission."""
        q = MediationResult.from_memory_write(
            {"record_id": "m2", "verdict": "quarantine", "status": "quarantined",
             "integrity_score": 0.3, "blocked": True,
             "quarantine_reason": "authority spoof"}
        )
        assert q.verdict is Verdict.QUARANTINE
        assert not q.allowed

    def test_withheld_memory_read_is_not_allowed(self):
        r = MediationResult.from_memory_read(
            {"memory_id": "m3", "verified": False, "withheld": True,
             "reason": "integrity below threshold"}
        )
        assert not r.allowed

    def test_context_rationale_is_surfaced_as_reason(self):
        """/context calls it `rationale`; /tool-call calls it `reason`."""
        r = MediationResult.from_decision(
            {"envelope_id": "e1", "decision": "block", "trust_label": "untrusted_data",
             "score": 0.8, "rationale": "imperative addressed to assistant",
             "patterns_matched": ["ignore_previous"], "content": ""}
        )
        assert r.reason == "imperative addressed to assistant"
        assert r.patterns_matched == ["ignore_previous"]

    def test_raise_for_decision_raises_on_block_and_carries_result(self):
        r = MediationResult(verdict=Verdict.BLOCK, decision="deny", reason="nope")
        with pytest.raises(SCMLBlocked) as exc:
            r.raise_for_decision()
        assert exc.value.result is r

    def test_raise_for_decision_returns_self_on_allow(self):
        r = MediationResult(verdict=Verdict.ALLOW, decision="allow")
        assert r.raise_for_decision() is r


# ── Fail policy (PRD §9) ──────────────────────────────────────────────────────

class TestFailPolicy:
    def test_unreachable_mediator_fails_closed_by_default(self, monkeypatch):
        """§9: a side-effect op must never treat a transport error as allow."""
        def boom(*a, **kw):
            raise httpx.ConnectError("connection refused")

        # Must patch Client.request, not httpx.request: the client no longer
        # calls the latter, so patching it left these passing only because
        # port 9 genuinely refuses — the stub never fired.
        monkeypatch.setattr(httpx.Client, "request", boom)
        client = SCMLClient("http://127.0.0.1:9")

        with pytest.raises(SCMLUnavailable):
            client.mediate_tool_call(
                session_id="s", tool_name="release_container", arguments={"id": "C1"}
            )

    def test_fail_open_is_opt_in_and_yields_a_non_allow_result(self, monkeypatch):
        def boom(*a, **kw):
            raise httpx.ConnectError("connection refused")

        # Must patch Client.request, not httpx.request: the client no longer
        # calls the latter, so patching it left these passing only because
        # port 9 genuinely refuses — the stub never fired.
        monkeypatch.setattr(httpx.Client, "request", boom)
        client = SCMLClient("http://127.0.0.1:9")

        result = client.mediate_context(session_id="s", content="doc", fail_open=True)
        assert result.verdict is Verdict.ERROR
        assert not result.allowed

    def test_http_error_status_also_fails_closed(self, stub_transport):
        stub_transport({"detail": "unauthorised"}, status=401)
        client = SCMLClient("http://localhost:8000")
        with pytest.raises(SCMLUnavailable):
            client.mediate_output(session_id="s", content="hi")


# ── Request construction ──────────────────────────────────────────────────────

class TestRequestConstruction:
    def test_fr_pe_04_argument_trust_labels_are_sent_when_supplied(self, stub_transport):
        calls = stub_transport({"decision": "allow", "reason": ""})
        client = SCMLClient("http://localhost:8000", api_key="sk-test")

        client.mediate_tool_call(
            session_id="s1",
            tool_name="release_container",
            arguments={"container_id": "C1"},
            argument_trust_labels={"container_id": "untrusted_data"},
        )

        body = calls[0]["json"]
        assert body["argument_trust_labels"] == {"container_id": "untrusted_data"}
        assert calls[0]["url"].endswith("/v1/mediate/tool-call")
        assert calls[0]["headers"]["X-API-Key"] == "sk-test"

    def test_trailing_slash_in_url_does_not_double_up(self, stub_transport):
        calls = stub_transport({"decision": "allow"})
        SCMLClient("http://localhost:8000/").mediate_context(session_id="s", content="x")
        assert calls[0]["url"] == "http://localhost:8000/v1/mediate/context"

    def test_no_api_key_sends_no_auth_header(self, stub_transport):
        calls = stub_transport({"decision": "allow"})
        SCMLClient("http://localhost:8000").mediate_context(session_id="s", content="x")
        assert "X-API-Key" not in calls[0]["headers"]


# ── Async parity ──────────────────────────────────────────────────────────────

class TestAsyncClient:
    async def test_async_client_normalises_identically(self, monkeypatch):
        class _FakeAsyncClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, url, **kwargs):
                return _FakeResponse({"decision": "require_approval.irreversible",
                                      "reason": "gated"})

        monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
        client = AsyncSCMLClient("http://localhost:8000")
        result = await client.mediate_tool_call(session_id="s", tool_name="wire_transfer")

        assert result.verdict is Verdict.APPROVAL_REQUIRED
        assert not result.allowed

    async def test_async_fails_closed_when_unreachable(self, monkeypatch):
        class _BoomClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, *a, **kw):
                raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx, "AsyncClient", _BoomClient)
        client = AsyncSCMLClient("http://localhost:8000")

        with pytest.raises(SCMLUnavailable):
            await client.mediate_memory_write(session_id="s", content="poison")


# ── Sanitize seam (FR-OR-03) ──────────────────────────────────────────────────

class TestSanitizeToolOutputSeam:
    """The sanitizer is deterministic and core-local: unlike the mediation
    endpoints it performs no I/O, so it must work with no server at all and
    preserve benign content byte-for-byte."""

    def test_sync_requires_no_network(self):
        client = SCMLClient("http://127.0.0.1:1")  # intentionally unreachable
        out = client.sanitize_tool_output("a<INFORMATION>evil</INFORMATION>b")
        assert out == "ab"

    def test_async_requires_no_network(self):
        import anyio

        async def _run():
            client = AsyncSCMLClient("http://127.0.0.1:1")
            return await client.sanitize_tool_output(
                "<INSTRUCTION>pay now</INSTRUCTION>ok"
            )

        assert anyio.run(_run) == "ok"

    def test_clean_content_is_unchanged(self):
        client = SCMLClient("http://127.0.0.1:1")
        text = "Q3 revenue was up 12%, and the deck is attached."
        assert client.sanitize_tool_output(text) == text

    def test_matches_the_direct_sanitizer(self):
        from trust_mediator.modules.output_redaction.sanitizer import (
            ToolOutputSanitizer,
        )

        payload = "here <INFORMATION>exfiltrate</INFORMATION> is the rest"
        client = SCMLClient("http://localhost:8000")
        assert client.sanitize_tool_output(payload) == ToolOutputSanitizer().sanitize(
            payload
        ).content


# ── The guard still routes through the client ─────────────────────────────────

def test_langchain_guard_delegates_transport_to_the_client(stub_transport):
    """
    The guard must keep counting transport failures rather than raising, or a
    network blip aborts the agent run instead of degrading.
    """
    from trust_mediator.integrations.langchain_guard import TrustMediatorGuard

    stub_transport({"decision": "deny.not_allowlisted", "reason": "not allowlisted"})
    guard = TrustMediatorGuard(api_url="http://localhost:8000")
    guard.on_tool_start({"name": "wire_transfer"}, "amount=1000")

    assert guard.stats["blocked"] == 1
    assert guard.stats["errors"] == 0
