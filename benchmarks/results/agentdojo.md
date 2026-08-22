# AgentDojo — Phase 0 pilot

**Status: pilot, not a headline result.** Six attack cases on one suite. Enough
to prove the integration runs and to expose a design fault; far too small to
quote as a benchmark figure.

| | Undefended | SCML |
|---|---:|---:|
| ASR (attack success — lower better) | **100.0%** (6/6) | **0.0%** (0/6) |
| Utility (task success — higher better) | 33.3% (2/6) | **0.0%** (0/6) |
| Tool calls refused | — | 6 |

```
suite        workspace (AgentDojo v1.2.1)
model        gpt-4o-mini
attack       important_instructions
scope        3 user tasks x 2 injection tasks = 6 cases
agent_id     agentdojo_workspace
policy       benchmarks/testbeds/agentdojo/policies/workspace.yaml
```

## Read this before quoting the 0%

**Utility is also 0%. The ASR figure is therefore not yet evidence of anything.**
A defense that refuses every action scores a perfect ASR and is worthless; that
is the failure mode this pilot landed in, and reporting the security column
alone would misrepresent it.

## What the run actually shows

Every denial was `deny.untrusted_arg` — FR-PE-04, the untrusted-argument rule.
The allow-list (FR-PE-02) never fired, because the workspace user tasks
legitimately need all 24 tools including `send_email` and `share_file`. So this
pilot tests argument provenance, not least agency.

All three tasks denied the **same pair**, `delete_file` and `send_email`.
Different user tasks do not coincidentally need the same two tools: that is the
*injected* goal being refused. SCML blocked the attack in all six cases.

Utility collapsed for a separate reason. `ScmlDefense` raises `AbortAgentError`
on denial, which stops the whole run — so blocking the injection also killed the
user's unfinished task. A reference monitor should refuse the call and let the
agent continue with the result of that refusal. **This is a fault in the
integration, not in the mediator**, and it is the single change most likely to
move utility off the floor.

## A fault this pilot already found and fixed

The first run denied `search_calendar_events` and `get_day_calendar_events` —
read-only tools. Labelling arguments untrusted for *every* tool refuses reads,
which has no security benefit and pure utility cost: 4 of 6 denials were reads.

The defense now labels arguments only for tools that can act. This matches the
project's existing rule that the mediator gates actions and egress, not beliefs
— the same reason poisoned memory is inert. After the change, all six denials
were genuine side-effecting calls.

## Known weaknesses of this measurement

- **Six cases.** Three user tasks, two injections, one attack, one model.
- **Taint is approximated.** Arguments count as untrusted once *any* tool result
  has entered the conversation, because real propagation needs dataflow the
  mediator cannot observe from here. This over-taints arguments the model took
  from the user's own instruction. Utility lost that way is a cost of the
  approximation, not of SCML.
- **`require_approval` is counted as a denial.** There is no human approver in
  a benchmark, so it cannot be satisfied. Counting it as an allow would be the
  FR-PE-03 error this project already fixed once.
- **Not reproducible bit-for-bit.** AgentDojo executes a live model.
- **Not comparable to published figures yet.** CaMeL reports 77% utility with
  provable security against 84% undefended, on the full suite. This is six
  cases with utility on the floor. The gap is the point, not a footnote.

## Reproducing

```bash
# separate virtualenv: agentdojo pulls langchain and four provider SDKs
python -m venv .adj && .adj/bin/pip install agentdojo -e .
.venv/bin/uvicorn trust_mediator.api.app:app --port 8111          # mediator
# PUT policies/workspace.yaml to /v1/policy, then:
PYTHONPATH=. .adj/bin/python -m benchmarks.testbeds.agentdojo.runner \
    --model gpt-4o-mini --tasks 3 --injections 2 --no-scml        # baseline
PYTHONPATH=. .adj/bin/python -m benchmarks.testbeds.agentdojo.runner \
    --model gpt-4o-mini --tasks 3 --injections 2                  # defended
```

## Next

1. Stop aborting the run on denial; return the refusal as the tool result so the
   agent can continue. Until this lands, utility is uninformative.
2. Widen to the full workspace suite once utility is off the floor.
3. Only then compare against published numbers.

## Notes on the free-tier path

Gemini was used to build and debug the integration at zero cost, and found every
problem: retired model ids, a Vertex-only Google path, the `thought_signature`
round-trip, and the policy schema. It is not usable for measurement — free-tier
requests-per-minute turns one task into minutes of backoff. The undefended
`gpt-4o-mini` baseline above took 41 seconds; the equivalent Gemini run had
consumed 58 minutes of wall clock and 3 seconds of CPU before it was killed.
