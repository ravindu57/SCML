---
paths:
  - "trust_mediator/modules/output_redaction/**"
  - "benchmarks/testbeds/agentdojo/**"
---

# Output redaction and the FR-OR-03 tool-output sanitizer

- **Tool-output sanitization is an inbound rewrite, not an egress verdict (FR-OR-03).** `ToolOutputSanitizer` (modules/output_redaction/sanitizer.py) strips *instruction framing* (``<INFORMATION>`` blocks, `IMPORTANT:` directive lines, dangling imperatives) from tool results *before* the agent model reads them. It is deliberately pattern-free with respect to adversarial vocabularies — patterns target how a payload is marked as an instruction, never the payload text, so it is not corpus-tuned (overfitting, benchmarks/README.md). A recognised injection must be removed, never passed through (§9 fail-closed in the inbound direction); unrecognised content passes through unchanged. It is deterministic and core-safe, and `client.sanitize_tool_output` must not pull in the server stack (structlog is optional with a stdlib fallback; `OutputRedactor` stays lazy). Use it through the *SDK method*, whose returned string is what a caller substitutes — it is the enforcement side, like `guard.redact`. `benchmarks/results/output_sanitizer.md` documents the seam, the measured slack `user_task_2` pilot (ASR 60% → 0% at no added utility cost) and the TypeScript mirror (portable regex engine, byte-for-byte parity corpus); do not quote a suite-level slack ASR number until the full `--sanitize` slack suite has been run.

**The sanitizer seam (FR-OR-03) targets exactly the slack gap.** The scanner
detects nothing and taint-by-overlap can't catch a payload the model *rewrites*
rather than copies; `ToolOutputSanitizer` + `client.sanitize_tool_output`
(strip instruction framing from tool results before the agent reads them) is
the prototype for closing it, wired as `--sanitize` in the agentdojo runner.
**It is core-safe by construction: structlog (a [server] extra) is optional
with a stdlib `logging` fallback, and `OutputRedactor` is lazy in
`output_redaction/__init__.py` — otherwise `sanitize_tool_output` breaks a
client-only install (that is a real bug the pilot caught).** Measured pilot on
slack `user_task_2` (`benchmarks/results/output_sanitizer.md`): undefended 100%
ASR, SCML 60% ASR (replicated twice — the measured rewrite gap), SCML
`--sanitize` 0% ASR with 5/5 tool results rewritten — at zero additional
utility cost, because honouring the invite from untrusted web content stays
correctly denied (`untrusted_arg`). That is a *single-task* result: **do not
quote a suite-level slack ASR number until the full `--sanitize` slack suite
has been run**.
