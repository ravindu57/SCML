---
name: kpi-report
description: Regenerate docs/EVAL_RESULTS.md — the §14.2, §14.2a/b and NFR tables — from the committed result files.
disable-model-invocation: true
---

Build `docs/EVAL_RESULTS.md` from result files only. Never type a number that is not read from a file.

1. Collect the newest result per testbed: a file under `benchmarks/results/v2/` wins over the frozen baseline in `benchmarks/results/`; show both when they differ, newest first.
2. Tables:
   - **§14.2 KPIs** (ASR, FPR, utility, detection, latency) per testbed, with target, measured value, PASS/FAIL, and the source file + commit.
   - **§14.2a** storage vs harm ASR for memory poisoning — both, always.
   - **§14.2b** enforcement coverage.
   - **Ablations**, always including the `no_tool_policy` row.
   - **NFRs** (PERF, AVAIL, OBS, SEC) with the evidence file, or `not measured`.
   - **AgentDojo coverage**: suites × attacks run, out of 4 × 17.
3. Copy the honesty caveats from `.claude/rules/benchmarks.md` next to the numbers they qualify (benign not attacked utility, scanner detects 0/1054, CaMeL better on both axes, sanitizer pilot is single-task).
4. List every miss explicitly in a "Not met" section at the top. Never claim anything in `CLAUDE.md` "Known gaps".
5. Run the `eval-analyst` agent over the inputs; mark any number it cannot recompute `[UNVERIFIED]`.
6. Show the diff of `docs/EVAL_RESULTS.md` before writing it.
