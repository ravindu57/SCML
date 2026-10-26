# Role plan: who does what, in which order

Phase 0 deliverable, 2026-10-15. The backlog numbers refer to `ANALYSIS.md` §9. Every session states "Session role: …" and does **one** item.

## Role matrix (from the continuation prompt, filled in)

| Level | Role | Backlog items | Claude Code features | Don't |
|---|---|---|---|---|
| 0 | **Recoverer** | Phase 0 (this analysis). Done when you approve it | plan mode, Explore subagents, throwaway copy for reproduction | edit the project |
| 1 | **Conversationalist** | Walk-throughs of findings before you approve fixes (e.g. why Sec #1 is Critical, how taint-by-value works). Also lets you explain every decision in a viva or interview | plain chat | decide without an ADR |
| 2 | **PRD person** | #10 doc honesty pass (define FR-OR-03; resolve the FR-MI-06 collision; promote the addendum from *proposed* or not); acceptance criteria for #12–#14 (how the DoS attacks are scored; held-out split for #15); the content side of #22 | plan mode, "interview me" | write code |
| 3 | **Architect** | design for #1 (policy schema), #2 (admin role / control-plane split, shadow), #6 (tenant data model and migration), #15 (utility vs ASR without tuning on the scored attacks), #16 (memory, needs an external or held-out corpus), #17 (classifier strategy), #19 (spill-to-disk, sandbox interface), #23 (deploy target) | plan mode, `security-reviewer` | write feature code |
| 4 | **CLI vibe coder** | #0 rescue (with your approval), #1, #3, #4, #5, #7, #8, #20, #21, #24, plus the implementation halves of #2, #6, #19 | plan → tests (FR/NFR IDs in names) → code; `/rewind` checkpoints; `security-reviewer` after each `trust_mediator/` change | touch frozen paths |
| 5 | **Debugger** | on demand: the "stale" results all reproduced, so nothing is failing today. Candidates: the 337k audit drops under the load harness; sklearn pickle version skew | regression test required | make unrelated changes |
| 6 | **Agentic builder** | #11 AgentDojo re-baseline (after #1–#8), #12 remaining attacks, #13 AgentDojo ablation, #14 slack `--sanitize` suite. All **paid**: cost estimate plus your approval first | `/run-eval`, `eval-analyst`, worktrees for parallel arms, a dynamic workflow for the attack sweep | overwrite baselines; tune policy on scored attacks |
| 7 | **Shipper** | #9 deploy defaults, #18 CI, #22 README and report, #23 deploy, release tag | GitHub Actions, `/code-review ultra` before release | add features |

## Corrections to the prompt's suggested roles

- **"Per-agent policy and tenant namespaces appear done; verify."** They're implemented (43ef16e, 9d3fb69), but tenancy is **incomplete**: memory, audit, gRPC and rate-limit are unscoped (Sec #6, #12). That's a CLI vibe coder item behind an Architect design (#6), not a done item.
- **"Memory poisoning 33.3% → < 10%".** The current figure is **20.8%**, reproduced today. The target is unchanged, and so is the rule against in-house tuning.
- **"§6.3 detection: check what `classifier_llm.md` concluded."** It concluded that the LLM backend is the only discriminative one (AUC 0.72), that it isn't shippable (AUC < 0.85, p95 2.2 s), and that the token-level route gate is a dead end. #17 is therefore Architect-first: a parser or fine-tuned model off the request path. Don't jump to the CLI vibe coder.
- **"Remaining AgentDojo attack types".** These move **after** the security fixes (#1–#8), because those fixes change the engine the numbers measure.
- **New, not in the prompt:** #0, rescuing the uncommitted TLS work and the stash media. It comes first because it's the only data-loss risk.

## Proposed session order (Phase 2)

1. #0 rescue (CLI vibe coder, approval needed)
2. #1 → #8 security items, each Architect-then-CLI where marked, with `security-reviewer` + `verifier` after each
3. #10 doc honesty pass (PRD person), so public docs stop overstating while the work continues
4. #11 re-baseline, then #12 / #13 / #14 (Agentic builder, paid, budget agreed)
5. #15 → #17 research items (Architect first)
6. #18, #19, #9 → #23 deploy (Shipper); #22 report last, once the numbers are final
7. #20, #21, #24 fill gaps between sessions
