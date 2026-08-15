# TrustMediator PRD — Addendum v1.1

**Status:** proposed
**Amends:** `TrustMediator_PRD (1).docx` (PRD v1.0)
**Supersedes:** nothing. v1.0 remains the source of truth for everything not
restated here.

---

## 0. Why this addendum exists

PRD v1.0 was written before the system had been measured against anything
external. It has held up well as a requirements spine — the FR-*/NFR-*
traceability convention is cited throughout the code and tests, and every
module maps to a numbered section.

It is no longer sufficient as a roadmap, for one reason that recurs in four
different forms: **v1.0 assumes detection is the defence.** Measurement shows
it is not. Every §14.2 acceptance target is detection-shaped, so the
specification cannot currently express the system's own strongest result.

The measurements that motivate each change are committed and reproducible:

| Evidence | Location |
|---|---|
| 1054 external indirect-injection cases | `benchmarks/results/injecagent.md` |
| In-house memory-poisoning corpus | `benchmarks/results/memory_poisoning.md` |
| Harm analysis of the same corpus | `benchmarks/results/memory_poisoning_harm.md` |
| Availability under injected faults | `benchmarks/results/soak.md` |
| Latency and throughput | `benchmarks/results/load.md` |

Nothing in this addendum lowers a v1.0 target. §14.2's memory-poisoning ASR
target of < 10% is retained unchanged and is still **not met** (33.3%).

---

## 1. §14.2a — Attack success must distinguish storage from harm

### Problem

v1.0 §14.2 sets a memory-poisoning ASR target without defining what constitutes
success *for the attacker*. The testbed reasonably interpreted it as "the
poisoned record was persisted `ACTIVE`", i.e. **stored**.

That measures the memory integrity layer in isolation, which is a legitimate
thing to measure, but it is not a measure of harm — and the gap is large:

| Family | Stored ASR | Harmful |
|---|---:|---:|
| `tool_hijack` | 83% | **0/6** |
| `authority_spoof` | 67% | **0/6** |

A memory instructing the agent to call `send_raw_smtp` is stored, but that tool
is not on the agent's allow-list, so a fully persuaded agent still cannot call
it. Reporting only the storage figure overstates operational risk; reporting
only the harm figure would move the goalposts. Both are required.

### Requirements

**FR-MI-06 (new).** The memory-poisoning testbed SHALL report two distinct
attack-success rates, and the evaluation harness SHALL refuse to publish one
without the other:

- **`memory_poisoning_asr` (storage)** — the poisoned record reached `ACTIVE`,
  i.e. is readable and able to steer future sessions.
- **`memory_harm_asr` (harm)** — the mediator would have permitted the
  attacker's actual goal, using the same standard the InjecAgent testbed
  applies to tool calls.

**FR-MI-07 (new).** Every case in an attack corpus SHALL be annotated with the
mediator gate its goal must defeat, drawn from a closed set:

| Vector | Must defeat |
|---|---|
| `tool` | tool allow-list, or untrusted-argument policy (FR-PE-04) |
| `output` | egress redaction (FR-OR-01) |
| `control` | the claim that a mediator control is disabled |
| `informational` | *nothing — no mediator gate exists on this path* |

The annotation SHALL be derived from the case's own text and asserted per-case
in tests, so that reclassification cannot silently change a published number.

### Acceptance criteria

| ID | Criterion | Current |
|---|---|---:|
| AC-14.2a-1 | `memory_poisoning_asr` < 10% | 33.3% ❌ |
| AC-14.2a-2 | `memory_harm_asr` (pessimistic) < 10% | 18.8% ❌ |
| AC-14.2a-3 | `memory_harm_asr` (gated paths only) < 5% | 2.5% ✅ |
| AC-14.2a-4 | Every corpus case carries a harm vector | 48/48 ✅ |

### Scope declaration — informational harm

**This is a deliberate limitation of the architecture, not a defect, and it is
declared in scope for disclosure and out of scope for mitigation.**

Eight corpus cases (`fact_replacement`, and two `persistent_directive` cases)
change what the agent *believes* or *says* without requiring a tool call or an
egress leak. The mediator gates actions and egress; it does not gate beliefs.
No layer in this system prevents them.

Consequently:

- Such cases SHALL be counted as **harmful** in the pessimistic total.
- They SHALL NOT be counted as blocked, defended, or mitigated.
- Any document quoting a harm ASR SHALL state the count of out-of-scope cases
  alongside it.

Crediting the mediator for attacks it never observes is the specific
overstatement §14 exists to prevent.

---

## 2. §14.2b — Enforcement coverage becomes a first-class KPI

### Problem

Every v1.0 §14.2 target is a detection metric (ASR, FPR). The ablation shows
detection contributes nothing on external data:

| Configuration | InjecAgent ASR |
|---|---:|
| `full_defence` | 0.0% |
| `no_scanner` | **0.0%** |
| `no_tool_policy` | **100.0%** |
| `undefended` | 100.0% |

The defence that holds is least agency. v1.0 has no KPI for it, so the
system's strongest and best-evidenced property is unmeasured by its own
acceptance criteria.

### Requirements

**FR-PE-06 (new).** The harness SHALL compute and report **enforcement
coverage**: the proportion of attack goals in a corpus that cannot be achieved
without a capability the agent does not hold.

```
enforcement_coverage = (attack goals denied by policy) / (attack goals requiring a tool)
```

**FR-PE-07 (new).** Reported enforcement coverage SHALL be accompanied by the
**residual set** — the goals achievable *with* the agent's legitimate
capabilities. These are confused-deputy cases, which least agency cannot
address by construction, and concealing them would make the KPI meaningless.

> Known residual, InjecAgent: `GitHubGetUserDetails` appears as both a user
> tool and an attacker tool upstream. Where an attacker reuses a capability the
> agent legitimately holds, policy cannot help.

### Acceptance criteria

| ID | Criterion | Current |
|---|---|---:|
| AC-14.2b-1 | Enforcement coverage ≥ 95% on the external corpus | 100% ✅ |
| AC-14.2b-2 | Residual set enumerated, not summarised | 1 case ✅ |
| AC-14.2b-3 | Ablation includes an enforcement-off row | present ✅ |

### Reporting constraint

**FR-PE-08 (new).** No document SHALL quote a headline ASR from a testbed that
varies enforcement without also presenting the `no_tool_policy` row. A 0% ASR
produced entirely by enforcement, presented as though it demonstrated
detection, is a false claim about which component works.

---

## 3. §6.3a — Classifier training data and evaluation protocol

### Problem

v1.0 §6.3 specifies a trained DeBERTa classifier. It names an architecture but
specifies **no training corpus and no evaluation protocol**. A requirement that
cannot be falsified cannot be satisfied, and two principled attempts failed
before this was noticed.

The shipped classifier is measurably worse than useless on external data:
ungated it scores attacks at mean **0.478** and benign content at **0.515** —
benign *higher* — with nothing approaching the 0.7 escalate threshold.

### Requirements

**FR-SC-06 (new).** Any injection classifier SHALL be trained exclusively on
data authored outside this project. The in-house memory-poisoning corpus SHALL
be reserved as a held-out evaluation set and SHALL NOT enter training under any
circumstance, including augmentation, template extraction, or hyperparameter
selection.

**FR-SC-07 (new).** A classifier SHALL NOT be shipped as a default backend
until it demonstrates, on a corpus disjoint from its training data:

| Metric | Threshold |
|---|---|
| Held-out ROC-AUC | ≥ 0.85 |
| Attack recall at operating threshold | ≥ 0.50 |
| False-positive rate at that threshold | ≤ 3% |
| Added p95 latency | ≤ 400 ms (NFR-PERF-01) |

**FR-SC-08 (new).** The stage-2 gate (`SCANNER_ML_GATE_THRESHOLD`) and the
classifier SHALL be evaluated **as a pair**. Reporting classifier quality
without stating the gate is invalid, because at the default gate the classifier
is consulted on 0 of 1054 external attacks — a mock oracle returning 1.0 changes
nothing.

### Rejected approaches — do not retry

Recorded so effort is not repeated. Both trained TF-IDF + LogisticRegression on
Apache-2.0 external corpora (`deepset/prompt-injections`,
`jackhhao/jailbreak-classification`), evaluated on InjecAgent held out:

| Approach | Held-out ROC-AUC | Why it failed |
|---|---:|---|
| Train on direct-injection prompts | 0.660 | Direct jailbreaks and indirect injection share almost no vocabulary |
| Same, embedded in tool-output carriers | 0.506 | Bag-of-words learns the carrier, not the instruction — a coin flip |

**Conclusion of record:** the discriminating signal is syntactic — *"is there an
imperative addressed to an assistant inside this data payload?"* — not lexical.
Bag-of-words cannot represent it. Further work in that family is out of scope.

### Permitted directions

1. `SCANNER_BACKEND=llm` — already implemented; requires an API key **and**
   `SCANNER_ML_GATE_THRESHOLD=0.0`. Cheapest untested option. Latency makes it
   viable only as **selective escalation** (memory writes, `risky_external`),
   not on the fast path.
2. Fine-tuned transformer per §6.3, trained off-device (GPU required).
3. Syntactic imperative detection (dependency parse / POS features), designed
   from the linguistic concept and never from inspecting the evaluation corpora.

### Gate policy until then

**FR-SC-09 (new).** `SCANNER_ML_GATE_THRESHOLD` SHALL remain at its default of
0.20 until a classifier satisfies FR-SC-07. Lowering it with the shipped
classifier is measured to be a net regression:

| | Default gate | Gate 0.0 |
|---|---:|---:|
| Detection (`no_tool_policy` ASR) | 100.0% | 80.3% |
| False-positive rate | 0.0% ✅ | **23.5%** ❌ |
| Utility | 100.0% ✅ | **76.5%** ❌ |

---

## 4. §16 — Production readiness annex

### Problem

v1.0 states NFR-SEC-03 (TLS/mTLS) and NFR-SEC-04 (secrets management) as
requirements with no design, no boundary definition, and no acceptance
criteria. §11 (sandboxed tool execution) specifies a component without
defining its interface to the host application. None can be verified as done.

### 16.1 Transport security — NFR-SEC-03

**Design.** Terminate TLS at the gateway; mTLS between mediator replicas and
between mediator and Postgres/Redis. Certificates from cluster PKI
(cert-manager), rotated ≤ 90 days.

| ID | Acceptance criterion |
|---|---|
| AC-16.1-1 | No mediator port accepts plaintext outside `localhost` |
| AC-16.1-2 | Peer certificate verification enabled on every outbound client |
| AC-16.1-3 | Rotation exercised without dropping a request (soak-verified) |
| AC-16.1-4 | Cipher suites restricted to TLS 1.3 |

### 16.2 Secrets — NFR-SEC-04

**Design.** No secret in env vars or images in production. External store
(Vault / cloud KMS) via CSI driver; `TRUST_MEDIATOR_API_KEYS` and
`LLM_SCANNER_API_KEY` sourced at runtime.

| ID | Acceptance criterion |
|---|---|
| AC-16.2-1 | `docker inspect` of a production image reveals no secret |
| AC-16.2-2 | Key rotation without restart |
| AC-16.2-3 | Revoked API key rejected within 60 s |
| AC-16.2-4 | Secrets never appear in logs, spans, or audit records |

> Precedent to preserve: `test_spans_never_carry_mediated_content` already
> enforces the analogous property for traces (NFR-OBS-01).

### 16.3 Sandboxed tool execution — §11

**Boundary definition (the gap in v1.0).** The mediator **authorises**; the
host application **executes**. v1.0 does not say which side sandboxes, so
neither does.

**Decision:** execution remains with the host. The mediator SHALL NOT gain an
execution path. §11 is therefore respecified as an *interface* requirement, not
a runtime component.

| ID | Acceptance criterion |
|---|---|
| AC-16.3-1 | Decisions carry machine-readable execution constraints (network egress, filesystem scope, wall-clock budget) |
| AC-16.3-2 | A reference sandbox host adapter demonstrates enforcement |
| AC-16.3-3 | Documentation states plainly that the mediator does not sandbox |

### 16.4 Audit durability — FR-AL-01

**Problem.** The queue is bounded; overflow drops decisions and records that it
did. Auditable under overload, not satisfied by it. A sustained overload is
still permanent loss.

| ID | Acceptance criterion |
|---|---|
| AC-16.4-1 | Spill-to-disk on queue pressure, replayed on recovery |
| AC-16.4-2 | Hash chain verifies across a spill/replay cycle |
| AC-16.4-3 | Zero dropped decisions under the §8.3 soak profile |
| AC-16.4-4 | Bounded disk use with a documented policy at the ceiling |

### 16.5 Operational readiness — NFR-OPS-01..03 (new)

| ID | Requirement |
|---|---|
| NFR-OPS-01 | Runbook per §9 fail mode, each naming the metric that detects it |
| NFR-OPS-02 | Documented multi-tenancy model (agent/tenant isolation in policy, memory, audit) |
| NFR-OPS-03 | Documented upgrade path preserving audit-chain continuity across schema changes |

---

## 5. What this addendum does not change

- The §5.2 core invariant. It is the property that holds under measurement and
  it is not weakened here.
- The §9 fail policy. Verified under six injected faults at 100.000%
  availability over 10,666 calls.
- The §14.2 memory-poisoning ASR target of < 10%. Still unmet at 33.3%.
- The traceability convention. Every requirement above follows it.
- The prohibition on tuning against the in-house corpus.

---

## 6. Revised acceptance summary

| Area | v1.0 status | With this addendum |
|---|---|---|
| Injection ASR (external) | not specified | ✅ 0.0% |
| Enforcement coverage | not specified | ✅ 100% |
| Memory ASR (storage) | ❌ 33.3% | ❌ 33.3% |
| Memory ASR (harm) | not specified | ❌ 18.8% pessimistic / ✅ 2.5% gated |
| Detection quality | assumed | ❌ specified and unmet (FR-SC-07) |
| Availability | unmeasured | ✅ 100.000% |
| Latency / throughput | ✅ | ✅ |
| Transport security | stated | ❌ specified, not built |
| Secrets management | stated | ❌ specified, not built |
| Sandbox | ambiguous | ⚠️ respecified as an interface |
| Audit durability | partial | ❌ specified, not built |

**v1.0 §14.4 acceptance remains not met.** The addendum does not change that;
it makes the remaining distance explicit and measurable rather than implicit.
