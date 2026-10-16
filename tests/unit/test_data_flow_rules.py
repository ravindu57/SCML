"""
FR-OR-02 / PRD §6.6: "an action is denied if it would move data of a
protected class to a sink the policy does not permit for that class."

Two things made this a no-op (security review Sec #11):

1. **The rules were never loaded.** The pipeline built one OutputRedactor with
   no config, so a policy's `redaction.data_flow_rules` had no effect.
2. **Missing meant allowed.** A protected class with no rule, or an empty one,
   could flow anywhere, and every shipped policy had `data_flow_rules: {}`.

Now each output call reads the caller's tenant policy, a protected class may
flow only where a rule permits it, and a malformed section or an unreadable
policy blocks labelled output (§9).
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from trust_mediator.core.pipeline import MediationPipeline
from trust_mediator.modules.audit_log.logger import AuditLogger
from trust_mediator.modules.output_redaction.redactor import OutputRedactor
from trust_mediator.modules.tool_policy.validation import validate_policy_document

ROOT = Path(__file__).resolve().parents[2]


def _redactor(**cfg) -> OutputRedactor:
    return OutputRedactor({"protected_classes": ["pii", "secret"], **cfg})


class TestDenyByDefault:
    def test_a_protected_class_with_no_rule_flows_nowhere(self):
        r = _redactor(data_flow_rules={}).redact("x", destination="user", data_class_labels=["pii"])
        assert r.blocked and "deny by default" in r.block_reason

    def test_an_empty_rule_flows_nowhere(self):
        r = _redactor(data_flow_rules={"secret": []}).redact("x", destination="user", data_class_labels=["secret"])
        assert r.blocked

    def test_a_permitted_destination_is_allowed_and_others_are_not(self):
        red = _redactor(data_flow_rules={"pii": ["user"]})
        assert not red.redact("x", destination="user", data_class_labels=["pii"]).blocked
        assert red.redact("x", destination="webhook", data_class_labels=["pii"]).blocked

    def test_labels_match_case_insensitively(self):
        red = _redactor(data_flow_rules={"pii": ["user"]})
        assert red.redact("x", destination="webhook", data_class_labels=["PII "]).blocked

    def test_a_class_named_only_in_a_rule_is_protected(self):
        red = _redactor(data_flow_rules={"health": ["clinician"]})
        assert red.redact("x", destination="user", data_class_labels=["health"]).blocked

    def test_unprotected_and_absent_labels_are_not_flow_checked(self):
        red = _redactor(data_flow_rules={})
        assert not red.redact("x", destination="webhook", data_class_labels=["public"]).blocked
        assert not red.redact("x", destination="webhook").blocked

    @pytest.mark.parametrize("bad", [{"pii": "user"}, ["pii"], {"pii": [1]}])
    def test_a_malformed_rule_set_blocks_labelled_output(self, bad):
        red = _redactor(data_flow_rules=bad)
        assert red.redact("x", destination="user", data_class_labels=["pii"]).blocked
        # Unlabelled output needs no flow decision.
        assert not red.redact("x", destination="user").blocked


class _Recording(AuditLogger):
    def __init__(self):
        super().__init__()
        self.logged = []

    def log(self, event):
        self.logged.append(event)


class _Loader:
    def __init__(self, policies, fail=False):
        self.policies, self.fail = policies, fail

    async def get_policy(self, tenant_id="default"):
        if self.fail:
            raise RuntimeError("policy store down")
        return self.policies[tenant_id]


def _policy(rules):
    return {"agents": {"default": {"allowed_tools": []}}, "memory": {},
            "redaction": {"protected_classes": ["pii"], "data_flow_rules": rules}}


@pytest.mark.asyncio
class TestPipelineReadsTheTenantsRules:
    async def _pipeline(self, loader):
        p = MediationPipeline(audit_logger=_Recording())
        p._loader = loader
        return p

    async def test_rules_are_per_tenant(self):
        p = await self._pipeline(_Loader({"acme": _policy({"pii": ["user"]}), "globex": _policy({})}))
        acme = await p.process_output("x", destination="user", data_class_labels=["pii"], tenant_id="acme")
        globex = await p.process_output("x", destination="user", data_class_labels=["pii"], tenant_id="globex")
        assert (acme.blocked, globex.blocked) == (False, True)

    async def test_unreadable_policy_blocks_labelled_output(self):
        p = await self._pipeline(_Loader({}, fail=True))
        r = await p.process_output("x", destination="user", data_class_labels=["pii"], tenant_id="acme")
        assert r.blocked

    async def test_unreadable_policy_still_redacts_unlabelled_output(self):
        p = await self._pipeline(_Loader({}, fail=True))
        r = await p.process_output("card 4111111111111111", destination="user", tenant_id="acme")
        assert not r.blocked and "4111111111111111" not in r.content
        assert p._audit.logged[-1].details["policy"] == "policy_unavailable"

    async def test_labels_are_recorded_in_the_audit_event(self):
        p = await self._pipeline(_Loader({"acme": _policy({})}))
        await p.process_output("x", destination="webhook", data_class_labels=["pii"], tenant_id="acme")
        assert p._audit.logged[-1].details["data_class_labels"] == ["pii"]


@pytest.mark.asyncio
async def test_the_http_route_passes_the_keys_tenant(monkeypatch):
    from httpx import ASGITransport, AsyncClient

    from trust_mediator.api.app import create_app
    from trust_mediator.api.dependencies import get_pipeline
    from trust_mediator.config import settings

    seen = {}

    class _P:
        async def process_output(self, content, **kw):
            seen.update(kw)
            return OutputRedactor().redact(content)

    monkeypatch.setattr(settings, "api_keys_raw", "acme@ops:sk-a")
    app = create_app()
    app.dependency_overrides[get_pipeline] = _P
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.post("/v1/mediate/output", json={"content": "x", "data_class_labels": ["pii"]},
                     headers={"X-API-Key": "sk-a"})
    assert seen["tenant_id"] == "acme"


class TestShippedPolicies:
    def test_default_policy_permits_pii_to_the_user_only(self):
        doc = yaml.safe_load((ROOT / "policies/default_policy.yaml").read_text())
        red = OutputRedactor(doc["redaction"])
        assert not red.redact("x", destination="user", data_class_labels=["pii"]).blocked
        assert red.redact("x", destination="webhook", data_class_labels=["pii"]).blocked
        assert red.redact("x", destination="user", data_class_labels=["secret"]).blocked


class TestValidation:
    @pytest.mark.parametrize(
        "section,fragment",
        [
            ([], "must be an object"),
            ({"data_flow_rules": {"pii": "user"}}, "data_flow_rules.pii"),
            ({"data_flow_rules": ["pii"]}, "'data_flow_rules' must map"),
            ({"protected_classes": "pii"}, "'protected_classes'"),
            ({"entropy_threshold": "high"}, "'entropy_threshold'"),
            ({"pii_patterns_enabled": "yes"}, "'pii_patterns_enabled'"),
        ],
    )
    def test_malformed_redaction_sections_are_refused(self, section, fragment):
        doc = {"agents": {"default": {"allowed_tools": []}}, "memory": {}, "redaction": section}
        errors = validate_policy_document(doc)
        assert any(fragment in e for e in errors), errors

    def test_a_well_formed_section_passes(self):
        doc = {"agents": {"default": {"allowed_tools": []}}, "memory": {},
               "redaction": {"protected_classes": ["pii"], "data_flow_rules": {"pii": ["user"]},
                             "entropy_threshold": 4.5, "pii_patterns_enabled": True}}
        assert validate_policy_document(doc) == []


class TestReviewHardening:
    @pytest.mark.asyncio
    async def test_a_tenant_cannot_switch_off_redaction(self):
        policy = {"agents": {"default": {"allowed_tools": []}}, "memory": {},
                  "redaction": {"pii_patterns_enabled": False, "entropy_threshold": 99,
                                "protected_classes": [], "data_flow_rules": {}}}
        p = MediationPipeline(audit_logger=_Recording())
        p._loader = _Loader({"acme": policy})
        r = await p.process_output("mail a@b.com card 4111111111111111", tenant_id="acme")
        assert "a@b.com" not in r.content and "4111111111111111" not in r.content

    def test_builtin_classes_stay_protected(self):
        red = OutputRedactor({"protected_classes": [], "data_flow_rules": {}})
        assert red.redact("x", destination="user", data_class_labels=["pii"]).blocked

    @pytest.mark.parametrize("label", ["pii​", "ＰＩＩ", " Pii "])
    def test_padded_and_width_variant_labels_are_still_pii(self, label):
        red = OutputRedactor({"data_flow_rules": {"pii": ["user"]}})
        assert red.redact("x", destination="webhook", data_class_labels=[label]).blocked

    def test_destinations_are_normalised_on_both_sides(self):
        red = OutputRedactor({"data_flow_rules": {"pii": ["User"]}})
        assert not red.redact("x", destination="user", data_class_labels=["pii"]).blocked

    @pytest.mark.asyncio
    async def test_a_non_string_rule_key_fails_closed_and_is_audited(self):
        policy = _policy({1: ["user"]})
        p = MediationPipeline(audit_logger=_Recording())
        p._loader = _Loader({"acme": policy})
        r = await p.process_output("x", data_class_labels=["pii"], tenant_id="acme")
        assert r.blocked
        assert p._audit.logged[-1].module.value == "output_redaction"

    def test_validation_refuses_a_non_string_rule_key(self):
        doc = {"agents": {"default": {"allowed_tools": []}}, "memory": {},
               "redaction": {"data_flow_rules": {1: ["user"]}}}
        assert any("class name" in e for e in validate_policy_document(doc))

    @pytest.mark.asyncio
    async def test_oversized_labels_are_rejected_at_the_api(self):
        from httpx import ASGITransport, AsyncClient

        from trust_mediator.api.app import create_app

        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
            r = await c.post("/v1/mediate/output", json={"content": "x", "data_class_labels": ["p" * 65]})
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_the_soak_redactor_fault_actually_injects():
    """It patched p._redactor, which the per-tenant path no longer calls, so
    the soak would have reported fail-closed without exercising egress."""
    from benchmarks.soak import faults

    p = MediationPipeline(audit_logger=_Recording())
    p._loader = _Loader({"default": _policy({"pii": ["user"]})})
    applied = faults.REDACTOR_DOWN.apply(p)
    try:
        r = await p.process_output("x", tenant_id="default")
    finally:
        applied.revert()
    assert r.blocked and "fail-closed" in r.block_reason
