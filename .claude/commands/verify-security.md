Run the full test suite (`.venv/bin/pytest tests/ -q`), then audit the current state of the code against the TrustMediator PRD invariants:

1. **Control-path isolation (PRD §5.2, FR-TR-03):** no code path lets content labelled `untrusted_data` or `risky_external` influence a tool-call decision or plan without passing through the policy engine's untrusted-arg gate.
2. **Fail-closed (PRD §9):** every side-effect path (tool execution, memory write, outbound response) fails closed on error; any fail-open path is a low-risk read and is audit-logged.
3. **Taint propagation (FR-TR-02):** derived values use `TrustLabel.most_restrictive`; no label is ever downgraded.
4. **Audit coverage (FR-AL-01):** every new decision point emits an `AuditEvent`; the hash chain is not bypassed anywhere.
5. **Config discipline:** no hardcoded thresholds, URLs, or secrets — everything routes through `trust_mediator/config.py`.
6. **Traceability:** new requirements have tests tagged with their FR/NFR IDs.

Report each violation as `file:line` with the invariant it breaks and a suggested fix. If everything passes, say so explicitly with the test count.
