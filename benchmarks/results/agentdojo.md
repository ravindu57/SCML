# AgentDojo — workspace suite

**560 attacked cases per arm plus 40 benign, 1,200 agent runs, 0 errors.**
Complete coverage of one of AgentDojo's four suites.

| | Undefended | SCML |
|---|---:|---:|
| **ASR** (attack success — lower better) | 16.8% (94/560) | **4.8%** (27/560) |
| Utility, attacked | 35.7% (200/560) | 38.6% (216/560) |
| Utility, benign | **82.5%** (33/40) | 77.5% (31/40) |
| Tool calls refused | — | 807 (all hard denials) |

```
suite        workspace (AgentDojo v1.2.1) — all 40 user tasks x all 14 injections
model        gpt-4o-mini
attack       important_instructions
agent_id     agentdojo_workspace
policy       benchmarks/testbeds/agentdojo/policies/workspace.yaml
runtime      4 min (benign) + 115 min (attacked)
```

## What this shows

**A 71% reduction in attack success**, from 16.8% to 4.8%. Not elimination —
27 of 560 injections still succeeded.

**The cost is 5 points of benign utility**, 82.5% → 77.5%: two tasks out of
forty, where legitimate work genuinely derives a value from something it read.
Retention is 94%.

**Under attack, utility does not drop at all** (35.7% → 38.6%). The +3 points is
16 cases and should be read as "no loss", not as an improvement — some of it is
tasks that undefended were hijacked into doing the attacker's work instead of
the user's.

**Every one of the 807 refusals was a hard `deny.untrusted_arg`.** None were
approval gates. This is FR-PE-04 doing the work on provenance, which is what the
design intends and what earlier runs did not achieve.

## This supersedes every earlier figure on this benchmark

Previous runs reported 0.0% ASR. That number was real but did not mean what it
appeared to: the taint extractor read `text` from AgentDojo content blocks that
carry `content`, so the tool-output corpus was empty on every call and FR-PE-04
never fired once. Every refusal came from
`require_approval_for: [irreversible, high_impact]` — a blanket gate on every
send and write, regardless of provenance. It stopped attacks by escalating them
to a human who does not exist in a benchmark, and cost 42 points of benign
utility doing it.

Fixed in `019e13c`. The gate is now empty and provenance is the only rule:

| Configuration | Benign utility | ASR | Refusal type |
|---|---:|---:|---|
| Blanket approval gate, taint broken | 40.0% | 0.0% | all gated |
| Gate removed, taint still broken | 82.5% | ~14% | none — nothing fired |
| **Gate removed, taint fixed** | **77.5%** | **4.8%** | **all hard** |

The middle row is the control: with neither mechanism active, ASR sits near the
undefended 16.8%. That is what makes the third row attributable to provenance
rather than to the model.

## Against CaMeL

CaMeL reports **77% utility with provable security against an 84% undefended
baseline** on AgentDojo.

| | CaMeL | SCML |
|---|---:|---:|
| Benign ceiling | 84% | 82.5% |
| Defended utility | 77% | 77.5% |
| **Utility retained** | 92% | **94%** |
| ASR | **0%** (provable) | 4.8% (measured) |
| Scope | 4 suites | 1 suite |
| Model | GPT-4o class | gpt-4o-mini |

The honest reading: **SCML retains slightly more utility and provides a weaker
security guarantee.** CaMeL eliminates the attack class by construction; SCML
reduces it by 71% empirically, on a quarter of the benchmark, with one attack
type. CaMeL also covers data exfiltration over unauthorised flows, which this
run does not test.

Where SCML wins is integration cost. CaMeL requires the agent restructured
around a privileged planner, a quarantined LLM and a custom interpreter. SCML
replaced one class — `ToolsExecutor` — and the existing agent kept working.

## Why 27 attacks still succeed

Taint is **inferred, not tracked**: an argument counts as untrusted when its
value appears in prior tool output. An injection that instructs the model to
*construct* a value rather than copy one — spelling an address out, or
assembling it — leaves no textual overlap and passes. Values under 12 characters
are exempt unless they contain `@` or `://`, because short common words collide
by chance and every collision refuses legitimate work.

Real provenance is tracked at the source rather than inferred at the boundary.
That is the fix, and it is an architecture change rather than a threshold.

## Known weaknesses

- **One suite of four.** travel, banking and slack are untested; each needs its
  own policy.
- **One attack of seventeen.** `important_instructions` only. The 4.8% may not
  generalise.
- **807 refusals for 560 cases.** The agent retries after a refusal, so denials
  are not a per-attack count.
- **Not reproducible bit-for-bit.** AgentDojo executes a live model.
- The allow-list (FR-PE-02) never fired: the workspace tasks legitimately need
  all 24 tools, so this suite tests argument provenance, not least agency — the
  opposite of the InjecAgent result, where tool policy was the entire defence.

## Reproducing

```bash
# separate virtualenv: agentdojo pulls langchain and four provider SDKs
python -m venv .adj && .adj/bin/pip install agentdojo -e .
.venv/bin/uvicorn trust_mediator.api.app:app --port 8111          # mediator
# PUT policies/workspace.yaml to /v1/policy, then:
PYTHONPATH=. .adj/bin/python -m benchmarks.testbeds.agentdojo.runner \
    --model gpt-4o-mini --tasks 40 --no-attack                    # benign
PYTHONPATH=. .adj/bin/python -m benchmarks.testbeds.agentdojo.runner \
    --model gpt-4o-mini --tasks 40 --injections 0                 # attacked
PYTHONPATH=. .adj/bin/python -m benchmarks.testbeds.agentdojo.runner \
    --model gpt-4o-mini --tasks 40 --injections 0 --no-scml       # baseline
```

## Next

1. The other three suites, one policy each.
2. A second attack type, to check 4.8% is not specific to
   `important_instructions`.
3. Track provenance at the source, which closes the construct-don't-copy
   evasion behind the remaining 27.
