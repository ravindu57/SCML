---
name: run-eval
description: Reproducible benchmark run into a new versioned result file — never over a committed baseline.
argument-hint: <testbed> [extra args]
disable-model-invocation: true
---

Testbed and arguments: **$ARGUMENTS**

Testbeds: `injecagent`, `memory_poisoning` (via `python -m benchmarks.cli`), `memory_poisoning_harm` (`python -m benchmarks.testbeds.memory_poisoning.harm_report`), `load` (`python -m benchmarks.load`), `soak` (`python -m benchmarks.soak`), `agentdojo` (`python -m benchmarks.testbeds.agentdojo.runner`), `classifier_eval`, `affordance_detector`. Read `benchmarks/README.md` for each one's flags.

1. **Cost check.** AgentDojo, the LLM classifier and anything with `SCANNER_BACKEND=llm` call a paid API. Estimate calls × tokens × price, show it, and wait for approval. Never read `.env` to find a key; ask the owner how the key is provided.
2. **Pin the run.** Record: HEAD commit and whether the tree is dirty (`git status --short`), Python and package versions (`pip freeze | sha256sum`), every `TRUST_MEDIATOR_*`/`SCANNER_*` env var in effect, seeds, model name, and the exact command line.
3. **Output path.** Always `--out benchmarks/results/v2` (create it). Rename the outputs to `<testbed>_<YYYY-MM-DD>[_<variant>].{md,json}`. If that name exists, add `_2`, `_3`. Never pass `--out benchmarks/results` — the frozen guard blocks it.
4. Run. For long runs use `run_in_background` and wait for the completion notification.
5. Write a sidecar `<same-name>.run.json` with everything from step 2, start/end time and the exit code.
6. Compare against the committed baseline for the same testbed in `benchmarks/results/` and report the delta. Always include the `no_tool_policy` ablation row where the testbed has one, and both storage and harm ASR for memory poisoning.
7. Run the `eval-analyst` agent on the new JSON. Report anything it cannot reproduce.
8. Do not edit any frozen file or `docs/EVAL_RESULTS.md` here; `/kpi-report` does that.
