# Progress reconciliation: "17 tests, 2 completed, plus 4 suites"

This is a Phase 0 deliverable, dated 2026-10-15. It is your recollection checked against what the repo shows.

> "**17 tests**, **2 completed**, plus **4 suites**; we used AgentDojo and InjecAgent."

## The evidence

**The installed AgentDojo registers exactly 17 attacks.** It lives at `~/.scml-adj/venv/.../agentdojo/attacks/`. I counted the `@register_attack` decorators:

| File | Count | Attacks |
|---|---:|---|
| `baseline_attacks.py` | 5 | `manual`, `direct`, `ignore_previous`, `system_message`, `injecagent` |
| `important_instructions_attacks.py` | 7 | `important_instructions`, `…_no_user_name`, `…_no_model_name`, `…_no_names`, `…_wrong_model_name`, `…_wrong_user_name`, `tool_knowledge` |
| `dos_attacks.py` | 5 | `dos`, `swearwords_dos`, `captcha_dos`, `offensive_email_dos`, `felony_dos` |

**The repo's own records agree:**
- `benchmarks/results/agentdojo.json:11` has `"attacks_available": 17`.
- `agentdojo.md` says "Two attacks of seventeen".
- `CHANGELOG.md:78`, `CLAUDE.md:113,259` and `blog-post-scml-vs-camel.md:38` all use 17 as the attack count.

**What was actually run:** six suite×attack cells out of a possible 68 (17 × 4).

| Attack | workspace | travel | banking | slack |
|---|:-:|:-:|:-:|:-:|
| `important_instructions` | ✅ | ✅ | ✅ | ✅ |
| `ignore_previous` | n/a | n/a | ✅ | ✅ |
| the other 15 | n/a | n/a | n/a | n/a |

**4 suites:** AgentDojo v1.2.1 ships four suites: workspace, travel, banking and slack. All four were run.

**InjecAgent:** a separate testbed with 1054 cases, run 2026-08-14 (`injecagent.md`). It was reproduced identically today.

**I searched for any other list of 17 items and found none.** I checked the PRD, the addendum, the README, the LaTeX report, the CHANGELOG, `benchmarks/README.md`, the `scml results/` and `Terminal Commands/` folders, and the leftover worktrees. Every "17" in the repo refers to the attack count. Two near-misses don't fit your sentence:
- InjecAgent's "17 benign" user cases. They are a corpus slice, not something you would "complete".
- Three test files that happen to contain 17 tests each: `test_fail_policy`, `test_api_auth` and `test_key_rotation`.

## Candidate readings

| Reading | 17 = | 2 = | 4 = | Fit | Evidence |
|---|---|---|---|---|---|
| **A** | AgentDojo attack types | attacks run (`important_instructions`, `ignore_previous`) | AgentDojo suites | **Strong** | registry count; `agentdojo.json:11`; `agentdojo.md` "Two attacks of seventeen"; the 6-cell matrix above |
| **B** | AgentDojo attack types | the two **benchmarks** run (AgentDojo + InjecAgent) | AgentDojo suites | Medium | fits your "we used AgentDojo and InjecAgent", but the number 2 is then coincidental |
| **C** | attacks | the **2 suites** that got the second attack (banking, slack) | suites | Weak | subsumed by A |
| **D** | tests in one test file | n/a | n/a | Very weak | no "2 completed" anywhere |

**Small nuance on reading A.** `manual` needs a human to type the injection, so **16 attacks can run unattended, and 14 of them are not done yet.** The five DoS attacks measure whether the agent can be made to stop working, not whether it can be hijacked. AgentDojo scores them differently, so they should be reported separately rather than folded into ASR.

## Rough cost of finishing reading A (an estimate, not a quote)

- **Data point:** `agentdojo.md:39` says the benign arms (97 tasks × 2 arms) cost **$0.15**. That's about $0.0008 per run.
- **Per attack:** 949 attacked cases × 2 arms (undefended + SCML) is about 1,900 runs. Attacked runs carry longer contexts, so call it $0.0008–0.003 per run, or **about $1.50–6 per attack**.
- **All 14 remaining automatable attacks:** **about $20–80** on gpt-4o-mini. This is `[UNVERIFIED]`. I'd run a single-suite pilot of one attack first and measure real token use.
- **Re-running `important_instructions` after the security fixes** (backlog item 11) adds about $5.
- **Runtime:** earlier runs backed off on 429 errors, so expect hours, not minutes.

Ordering matters. The policy-validation and label fixes (ANALYSIS §9, items 1–8) change the engine those numbers measure. Run the new attacks **after** those fixes. Otherwise both the old attacks and the new ones have to be re-run.

## Question for you

1. Is **reading A** what you meant: 17 = AgentDojo attack types, 2 = the attacks run so far, 4 = the AgentDojo suites? Or did "2 completed" mean the two benchmarks, AgentDojo and InjecAgent (reading B)?
2. If A: should the goal be **all 14 remaining automatable attacks**, or a subset? For example, the 6 `important_instructions` variants plus `tool_knowledge`, `direct` and `system_message` (9 attacks), with the 5 DoS attacks as a separate, cheaper follow-up.
3. What budget ceiling should I stay under for paid runs?
