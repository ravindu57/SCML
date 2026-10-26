---
paths:
  - "trust_mediator/modules/tool_policy/**"
  - "trust_mediator/modules/policy_store/**"
  - "policies/**"
  - "trust_mediator/api/routers/policy.py"
  - "benchmarks/testbeds/agentdojo/policies/**"
---

# Tool policy and policy store (FR-PE-*, FR-OR-02, FR-CP-02)

- **A malformed policy must never widen authority (§5.2, §9).** Two layers,
  both required: `tool_policy/validation.py` rejects a bad document before it
  is stored, loaded from YAML or rolled back to, and `PolicyEngine` denies on
  any shape it does not recognise and never raises (an unexpected error is an
  audited `mediator_error`, because a 500 reads as permission to a fail-open
  client). There is no `untrusted_arg_policy: allow`. An absent `allowed_tools`
  denies. Keep validation and the engine's shape checks in step;
  `test_policy_fail_closed.py` pins both and validates every shipped policy.
- **FR-OR-02 data-flow rules are per tenant and deny by default.** `_process_output` reads only
  `protected_classes`/`data_flow_rules` from the tenant policy; PII/entropy settings stay built-in
  so a tenant cannot disable redaction. Policy `memory`/`scanner` sections are NOT enforced (env
  governs). `test_data_flow_rules.py` pins this.

- **Per-agent policy updates exist; whole-document PUT still clobbers.**
  `PUT /v1/policy/agents/{id}` replaces one agent and leaves the rest alone, so
  two teams can administer different agents on one mediator. `PUT /v1/policy`
  still replaces the entire document including the `agents` map — it is for
  bootstrapping and wholesale changes, not routine administration.
  The concurrency is not incidental: the read-modify-write lives in
  `PolicyRepository.upsert_agent` inside one transaction, guarded by a unique
  constraint on `base_version_id`. Doing it in the router would reintroduce the
  same lost update with a millisecond window instead of a permanent one.
  Constraining `version_number` instead does **not** work and was measured
  failing: the document is read from the active row while the number comes from
  `max(version_number)`, so a writer can read v3, find max=4, write v5 and
  erase everything v4 added.
  Exhausting the retries raises rather than writing — a caller that sees an
  error can retry; one whose write vanished cannot know to.
  The `default` agent is refused through this endpoint: it is the deny-all
  fallback every unconfigured agent lands on, so widening it there would grant
  authority to agents nobody has configured.
- Policy identity is per `agent_id`, and an unknown `agent_id` falls back to
  `default` (deny-all). That is the correct fail-closed default, but it means
  "install the SDK" never means "it works" — a new integration is fully denied
  until someone writes policy for it. Grant authority per *capability*, not per
  system: give each workflow or sub-agent its own id, so a compromised step
  cannot borrow another's authority. One shared id makes the allow-list the
  union of everything any part of the system needs, which is the opposite of
  least agency. `demo-agent/` shows the pattern.
