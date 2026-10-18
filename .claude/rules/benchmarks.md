---
paths:
  - "benchmarks/**"
  - "README.md"
  - "SECURITY.md"
  - "CHANGELOG.md"
  - "blog-post-scml-vs-camel.md"
  - "PRD_v1.1_ADDENDUM.md"
  - "docs/**"
  - "SCML_Project_Report.tex"
---

# Measured state (PRD §14.2) — the full text. Read before quoting any number anywhere.

- AgentDojo covers **all four suites** but only **two attacks of seventeen**
  (`important_instructions` on all four; `ignore_previous` on banking and
  slack). `manual` needs a human, so 14 automatable attacks remain. Do not
  describe AgentDojo coverage as complete — see "Measured state". The InjecAgent testbed **does** exist
  (`benchmarks/testbeds/injecagent/`, 1054 external cases) — see "Measured state"

## Measured state (PRD §14.2) — do not overstate

`benchmarks/results/memory_poisoning.md` is the committed baseline. As of the
last run the memory integrity layer measures **20.8% ASR against a < 10%
target**; §14.2 acceptance is NOT met. That is down from 33.3%: the
control-plane conflict detector (FR-MI-06, `consistency_checker._check_control_conflict`)
halved the two worst families it is structurally equipped for —
`tool_hijack` 83% → 33%, `authority_spoof` 67% → 17% — with FPR still 0% and
utility 100%. Do not regress it by loosening the gate; any change to the
scorer, its thresholds or the detector must re-run this benchmark and write a new versioned result
file under benchmarks/results/v2/ (ADR-0001: committed baselines are frozen and never overwritten).

**That 20.8% is storage, not harm.** `benchmarks/results/memory_poisoning_harm.md`
applies the InjecAgent standard (success = the mediator would have let the goal
through): 0/13 tool cases and 0/22 control-bypass cases are harmful; 1/5 output
cases leak; 8 informational cases have no mediator gate at all. Pessimistic
total **18.8%**. Report both numbers — quoting only the harm figure is moving
the goalposts, quoting only storage overstates a record the control path never
reads. Never count the 8 informational cases as defended; the mediator gates
actions and egress, not beliefs.


When changing the scorer, thresholds or detectors, re-run the benchmark and
write a new versioned result file under benchmarks/results/v2/ (ADR-0001: committed baselines are frozen and never overwritten). Do not tune weights or add regex patterns against
this corpus: it was written in-house, so that is overfitting, not a result.

**AgentDojo, all four suites** (`benchmarks/results/agentdojo.md`): ASR
**29.0% -> 7.3%** across 949 attacked cases, a 75% reduction, for **19% of
benign task completion** (74.2% -> 59.8%).

Quote the *benign* utility comparison, never the attacked one. Under attack the
undefended baseline is already wrecked by hijacking, so the same run reads as
97% utility retained instead of 81% — flattering and misleading. Earlier
revisions of the result file made exactly that error.

Three things about the number are load-bearing:

- **The technique has a domain boundary, and it is measured.** banking is
  100% (71 attacks, 0 succeeded) because moving money needs an IBAN the
  attacker must name, and a named identifier appears verbatim in tool output.
  slack is 52% and loses 30% of benign utility because its tasks *are* "fetch
  untrusted content and act on it" — `user_task_2` says "invite Dora, her email
  is on her website". `invite_user_to_slack` was refused in 19 of 21 tasks. That
  is the rule working correctly on a workflow indistinguishable from an attack.
- **Security and utility cost are independent.** travel has the second-best ASR
  reduction and the *worst* utility cost (64% retained). Do not infer one from
  the other.
- **Defended numbers replicate, baselines do not.** Two full Phase 1 runs gave
  identical SCML figures (banking 0.0%, slack 30.5%) while undefended baselines
  moved 3-5 points. Differences of that size are noise.

Against CaMeL's 77%/84%: **CaMeL is better on both axes** — 0% provable vs 7.3%
measured, 92% utility retained vs 81%. SCML's advantage is integration cost
alone (replace one class vs rebuild the agent around an interpreter). Do not
present it as a security result.

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

Two attacks of seventeen: `important_instructions` (all four suites) and
`ignore_previous` (banking 20.1% -> 0.0%, slack 17.1% -> 10.5%).

**External validation now exists.** `benchmarks/results/injecagent.md` is the
committed baseline for 1054 third-party indirect-injection cases (InjecAgent,
ACL 2024, MIT, vendored). All five §14.2 KPIs PASS — but never quote the
headline without the ablation:

- `no_scanner` is also 0.0%; `no_tool_policy` is **100.0%**. Tool policy is the
  *entire* defence. **The injection scanner detects 0 of 1054 attacks.**
- Do not describe the 0% ASR as evidence the scanner works. It is evidence that
  least agency holds while detection contributes nothing.

**§6.3 is broken in two independent ways, both measured** (details and the
already-rejected fixes are in `benchmarks/README.md`):

1. **Stage 2 is unreachable.** `scan()` runs the classifier only when the regex
   pre-filter scores at or above `SCANNER_ML_GATE_THRESHOLD` (default 0.20);
   992/1054 attacks score exactly 0.0. A mock oracle returning 1.0 is consulted
   on **0 of 1054**. So `SCANNER_BACKEND=llm` buys nothing on the
   `untrusted_data` path without also lowering the gate — it changes which
   classifier runs, not whether it runs. `risky_external` bypasses the gate and
   is always classified, so an LLM backend does work there today.
2. **The classifier is anti-discriminative.** Ungated, it scores attacks at 0.478
   and benign at 0.515 — benign *higher*. Measured: `SCANNER_ML_GATE_THRESHOLD=0.0`
   on InjecAgent catches 19.7% more attacks but takes FPR 0.0% → 23.5% and
   utility 100% → 76.5%, flipping two KPIs to FAIL. Neither fix works alone, so
   the gate default stays at 0.20 until a classifier earns opening it.

Two TF-IDF training approaches on external Apache-2.0 corpora were measured and
rejected (held-out AUC 0.660 and 0.506 — the latter a coin flip). Bag-of-words
cannot represent the discriminating signal, which is syntactic ("is there an
imperative addressed to an assistant in this payload?"). Do not retry that
family. **The LLM backend is now measured, not untested** (gpt-4o-mini, held-out
InjecAgent, `benchmarks/results/classifier_llm.md`): it is the only backend that
separates the classes — ROC-AUC 0.72 vs the heuristic's 0.35 (anti-discriminative)
— but it is still **not FR-SC-07 shippable** (AUC 0.72 < 0.85, and any threshold
that clears FPR ≤ 3% abandons recall), and it fails NFR-PERF-01 outright
(p95 ≈ 2.2 s vs 400 ms). It cannot sit on the synchronous request path even if
accuracy improved. The untested combination is a *fast CPU-bound syntactic gate*
that routes only genuinely ambiguous payloads to the LLM — never the request
path. **That gate is now measured and is a dead end at token level**
(`SyntacticRouteGate`, `python -m benchmarks.classifier_eval.evaluate --route`,
see `classifier_llm.md`): the injected instruction lives *inside a quoted JSON
value* of tool output, so a gate that strips quotes (naive "quoted = content")
drops 95.2% of attacks (only 4.8% preserved), while one that searches the full
payload preserves 95.5% of attacks but routes 94% of *all* payloads to the LLM
(saves no latency — benign data shares the same closed-class command vocabulary,
so token-level can't separate command-mood from declarative use of the same
verb). Only a real dependency/POS parser that recognises imperative *mood* (the
`_syntactic_score` seam) or a fine-tuned transformer can resolve it; both need
resources this core install deliberately excludes.

Any classifier work must train on external data and evaluate against the
in-house corpus as a held-out set, never the reverse.

**The tool-affordance imperative detector is measured and is a no-go**
(`benchmarks/affordance_detector/`, `benchmarks/results/affordance_detector.md`).
It is CPU-only (spaCy parse + bge-small via onnxruntime, `[detect]` extra) and
reaches held-out InjecAgent AUC **0.779** with hard negatives, at 158 ms p95.
That is better than any shipped backend, but short of FR-SC-07 (0.85, and 7.6%
FPR at the externally frozen threshold). Its own ablation refutes the
"imperative x affordance" product: tool similarity *alone* scores 0.834, and the
mood term lowers it. Do not describe the product score as a contribution. It
does not reach memory poisoning at all (0% recall), because poisoned memory is
phrased as notes and facts. Any follow-up change needs a held-out set this run
did not see.
